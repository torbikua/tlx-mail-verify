import email
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from datetime import datetime
import dkim
import spf
import dns.resolver
from typing import Dict, Any, Optional, List
from src.utils.logger import logger


class EmailParser:
    """Parse and validate email messages"""

    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5

    def parse_email(self, raw_email: bytes) -> Dict[str, Any]:
        """
        Parse raw email and extract all relevant information

        Args:
            raw_email: Raw email bytes

        Returns:
            Dictionary with parsed email data
        """
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)

            # Extract basic headers
            from_header = msg.get('From', '')
            from_name, from_address = parseaddr(from_header)

            result = {
                'message_id': msg.get('Message-ID', ''),
                'subject': msg.get('Subject', ''),
                'from_name': from_name,
                'from_address': from_address,
                'to_address': msg.get('To', ''),
                'date': self._parse_date(msg.get('Date')),
                'received_headers': self._parse_received_headers(msg),
                'sender_ip': self._extract_sender_ip(msg),
                'return_path': msg.get('Return-Path', ''),
                'reply_to': msg.get('Reply-To', ''),
                'headers': dict(msg.items()),
                'body_text': self._get_body(msg, 'plain'),
                'body_html': self._get_body(msg, 'html'),
                'authentication_results': self.parse_authentication_results(msg),
            }

            logger.info(f"Successfully parsed email: {result['message_id']}")
            return result

        except Exception as e:
            logger.error(f"Failed to parse email: {e}")
            raise

    def validate_dkim(self, raw_email: bytes) -> Dict[str, Any]:
        """
        Validate DKIM signature

        Args:
            raw_email: Raw email bytes

        Returns:
            Dictionary with DKIM validation results
        """
        try:
            # Perform DKIM verification
            result = dkim.verify(raw_email)

            # Extract DKIM signature details
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            dkim_signature = msg.get('DKIM-Signature', '')

            dkim_info = {
                'valid': result,
                'signature_present': bool(dkim_signature),
                'signature': dkim_signature,
                'details': self._parse_dkim_signature(dkim_signature) if dkim_signature else {}
            }

            logger.info(f"DKIM validation result: {'PASS' if result else 'FAIL'}")
            return dkim_info

        except Exception as e:
            logger.error(f"DKIM validation failed: {e}")
            return {
                'valid': False,
                'signature_present': False,
                'error': str(e)
            }

    def validate_spf(self, sender_ip: str, from_domain: str, helo_domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate SPF record

        Args:
            sender_ip: IP address of the sender
            from_domain: Domain from the From header
            helo_domain: HELO/EHLO domain (optional)

        Returns:
            Dictionary with SPF validation results
        """
        try:
            # Perform SPF check
            result, explanation = spf.check2(
                i=sender_ip,
                s=from_domain,
                h=helo_domain or from_domain
            )

            # Get SPF record
            spf_record = self._get_spf_record(from_domain)

            spf_info = {
                'valid': result == 'pass',
                'result': result,
                'explanation': explanation,
                'record': spf_record,
                'sender_ip': sender_ip,
                'domain': from_domain
            }

            logger.info(f"SPF validation result: {result} for {from_domain}")
            return spf_info

        except Exception as e:
            logger.error(f"SPF validation failed: {e}")
            return {
                'valid': False,
                'result': 'error',
                'error': str(e),
                'sender_ip': sender_ip,
                'domain': from_domain
            }

    def validate_dmarc(self, from_domain: str) -> Dict[str, Any]:
        """
        Check DMARC policy

        Args:
            from_domain: Domain from the From header

        Returns:
            Dictionary with DMARC policy information
        """
        try:
            dmarc_domain = f"_dmarc.{from_domain}"

            try:
                answers = self.dns_resolver.resolve(dmarc_domain, 'TXT')
                dmarc_records = [str(rdata).strip('"') for rdata in answers
                                if str(rdata).startswith('v=DMARC1')]

                if dmarc_records:
                    dmarc_record = dmarc_records[0]
                    policy = self._parse_dmarc_record(dmarc_record)

                    dmarc_info = {
                        'valid': True,
                        'record': dmarc_record,
                        'policy': policy.get('p', 'none'),
                        'subdomain_policy': policy.get('sp', 'none'),
                        'percentage': policy.get('pct', '100'),
                        'alignment': {
                            'spf': policy.get('aspf', 'r'),
                            'dkim': policy.get('adkim', 'r')
                        },
                        'reporting': {
                            'aggregate': policy.get('rua', []),
                            'forensic': policy.get('ruf', [])
                        }
                    }

                    logger.info(f"DMARC record found for {from_domain}: policy={policy.get('p')}")
                    return dmarc_info
                else:
                    return {
                        'valid': False,
                        'error': 'No DMARC record found'
                    }

            except dns.resolver.NXDOMAIN:
                return {
                    'valid': False,
                    'error': 'No DMARC record found (NXDOMAIN)'
                }

        except Exception as e:
            logger.error(f"DMARC validation failed: {e}")
            return {
                'valid': False,
                'error': str(e)
            }

    def _parse_received_headers(self, msg: email.message.EmailMessage) -> List[Dict[str, str]]:
        """Parse Received headers to trace email path"""
        received_headers = []
        for header in msg.get_all('Received', []):
            received_headers.append({
                'header': header,
                'parsed': self._parse_received_header(header)
            })
        return received_headers

    def _parse_received_header(self, header: str) -> Dict[str, str]:
        """Parse a single Received header (supports both IPv4 and IPv6)"""
        result = {}

        # Extract from
        from_match = re.search(r'from\s+([^\s]+)', header)
        if from_match:
            result['from'] = from_match.group(1)

        # Extract by
        by_match = re.search(r'by\s+([^\s]+)', header)
        if by_match:
            result['by'] = by_match.group(1)

        # Extract IP (supports both IPv4 and IPv6)
        # Try IPv6 first
        ipv6_match = re.search(r'\[([0-9a-fA-F:]+)\]', header)
        if ipv6_match and ':' in ipv6_match.group(1):
            result['ip'] = ipv6_match.group(1)
        else:
            # Try IPv4
            ipv4_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', header)
            if ipv4_match:
                result['ip'] = ipv4_match.group(1)

        # Extract date
        date_match = re.search(r';\s*(.+)$', header)
        if date_match:
            result['date'] = date_match.group(1).strip()

        return result

    def _extract_sender_ip(self, msg: email.message.EmailMessage) -> Optional[str]:
        """Extract sender IP from Received headers - EXTERNAL IP only (supports both IPv4 and IPv6)"""
        received_headers = msg.get_all('Received', [])
        if received_headers:
            # Look through Received headers from bottom to top (oldest first)
            for received in reversed(received_headers):
                # Try IPv4 (format: [192.168.1.1])
                ipv4_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
                if ipv4_match:
                    ip = ipv4_match.group(1)
                    # Skip private/local IPs
                    if not self._is_private_ip(ip):
                        return ip

                # Try IPv6 (format: [2a01:111:f403:c201::3])
                ipv6_match = re.search(r'\[([0-9a-fA-F:]+)\]', received)
                if ipv6_match and ':' in ipv6_match.group(1):
                    ip = ipv6_match.group(1)
                    # Skip link-local IPv6 (fe80::)
                    if not ip.startswith('fe80:'):
                        return ip
        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse email date header"""
        if not date_str:
            return None
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
        except Exception:
            return None

    def _get_body(self, msg: email.message.EmailMessage, content_type: str) -> str:
        """Extract email body by content type"""
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == f'text/{content_type}':
                        return part.get_content()
            else:
                if msg.get_content_type() == f'text/{content_type}':
                    return msg.get_content()
        except Exception as e:
            logger.warning(f"Failed to extract {content_type} body: {e}")
        return ''

    def _get_spf_record(self, domain: str) -> Optional[str]:
        """Get SPF record for domain"""
        try:
            answers = self.dns_resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    return txt
        except Exception as e:
            logger.warning(f"Failed to get SPF record for {domain}: {e}")
        return None

    def _parse_dkim_signature(self, signature: str) -> Dict[str, str]:
        """Parse DKIM signature header"""
        result = {}
        parts = signature.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                result[key.strip()] = value.strip()
        return result

    def _parse_dmarc_record(self, record: str) -> Dict[str, Any]:
        """Parse DMARC record"""
        result = {}
        parts = record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                result[key.strip()] = value.strip()
        return result

    def parse_authentication_results(self, msg: email.message.EmailMessage) -> Dict[str, Any]:
        """
        Parse Authentication-Results header from Gmail/other mail servers
        This contains the results of SPF, DKIM, and DMARC checks performed by the receiving server

        Args:
            msg: Parsed email message

        Returns:
            Dictionary with authentication results
        """
        auth_results = {
            'spf': {'result': 'none', 'details': {}},
            'dkim': {'result': 'none', 'details': {}},
            'dmarc': {'result': 'none', 'details': {}}
        }

        try:
            # Get Authentication-Results header(s)
            auth_headers = msg.get_all('Authentication-Results', [])

            for header in auth_headers:
                header_lower = header.lower()

                # Parse SPF result
                spf_match = re.search(r'spf=(\w+)(?:\s+\(([^)]+)\))?', header_lower)
                if spf_match:
                    auth_results['spf']['result'] = spf_match.group(1)
                    # Extract IP from SPF details
                    ip_match = re.search(r'designates\s+([0-9a-fA-F:.]+)\s+as\s+permitted', header)
                    if ip_match:
                        auth_results['spf']['details']['sender_ip'] = ip_match.group(1)
                    # Extract domain
                    domain_match = re.search(r'smtp\.mailfrom=([^\s;]+)', header)
                    if domain_match:
                        auth_results['spf']['details']['domain'] = domain_match.group(1)

                # Parse DKIM result
                dkim_match = re.search(r'dkim=(\w+)(?:\s+header\.i=@([^\s;]+))?(?:\s+header\.s=([^\s;]+))?(?:\s+header\.b=([^\s;]+))?', header_lower)
                if dkim_match:
                    auth_results['dkim']['result'] = dkim_match.group(1)
                    if dkim_match.group(2):
                        auth_results['dkim']['details']['domain'] = dkim_match.group(2)
                    if dkim_match.group(3):
                        auth_results['dkim']['details']['selector'] = dkim_match.group(3)
                    if dkim_match.group(4):
                        auth_results['dkim']['details']['signature'] = dkim_match.group(4)

                # Parse DMARC result
                dmarc_match = re.search(r'dmarc=(\w+)(?:\s+\(p=(\w+)(?:\s+sp=(\w+))?(?:\s+dis=(\w+))?\))?(?:\s+header\.from=([^\s;]+))?', header_lower)
                if dmarc_match:
                    auth_results['dmarc']['result'] = dmarc_match.group(1)
                    if dmarc_match.group(2):
                        auth_results['dmarc']['details']['policy'] = dmarc_match.group(2)
                    if dmarc_match.group(3):
                        auth_results['dmarc']['details']['subdomain_policy'] = dmarc_match.group(3)
                    if dmarc_match.group(4):
                        auth_results['dmarc']['details']['disposition'] = dmarc_match.group(4)
                    if dmarc_match.group(5):
                        auth_results['dmarc']['details']['domain'] = dmarc_match.group(5)

            logger.info(f"Parsed authentication results - SPF: {auth_results['spf']['result']}, "
                       f"DKIM: {auth_results['dkim']['result']}, DMARC: {auth_results['dmarc']['result']}")

        except Exception as e:
            logger.error(f"Failed to parse authentication results: {e}")

        return auth_results

    def extract_eml_attachment(self, raw_email: bytes) -> Optional[bytes]:
        """
        Extract .eml file from email attachments

        Args:
            raw_email: Raw email bytes

        Returns:
            Raw bytes of the .eml attachment or None if not found
        """
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)

            if not msg.is_multipart():
                logger.debug("Email is not multipart, no attachments")
                return None

            for part in msg.walk():
                # Skip multipart containers
                if part.get_content_maintype() == 'multipart':
                    continue

                # Check for message/rfc822 content type (forwarded emails) FIRST
                if part.get_content_type() == 'message/rfc822':
                    logger.info("Found forwarded email (message/rfc822)")
                    # For message/rfc822, get_payload() returns the message object or list
                    payload = part.get_payload()

                    # Handle both single message and list of messages
                    if isinstance(payload, list) and len(payload) > 0:
                        forwarded_msg = payload[0]
                    else:
                        forwarded_msg = payload

                    if forwarded_msg:
                        # Convert back to bytes
                        try:
                            return forwarded_msg.as_bytes()
                        except AttributeError:
                            # If as_bytes() doesn't work, try as_string().encode()
                            return forwarded_msg.as_string().encode('utf-8')

                # Get content disposition
                content_disposition = part.get('Content-Disposition', '')
                filename = part.get_filename()

                # Check if it's an attachment
                if 'attachment' in content_disposition.lower() or filename:
                    # Check if filename ends with .eml
                    if filename and filename.lower().endswith('.eml'):
                        logger.info(f"Found .eml attachment: {filename}")
                        # Get the attachment content
                        payload = part.get_payload(decode=True)
                        return payload

            logger.debug("No .eml attachment found in email")
            return None

        except Exception as e:
            logger.error(f"Failed to extract .eml attachment: {e}")
            return None

    def extract_forwarded_email(self, raw_email: bytes) -> Optional[Dict[str, Any]]:
        """
        Extract information from a forwarded email including SPF/DKIM/DMARC data
        Now prioritizes .eml attachments over text parsing

        Args:
            raw_email: Raw email bytes

        Returns:
            Dictionary with forwarded email data or None if not forwarded
        """
        try:
            # First, try to extract .eml attachment
            eml_attachment = self.extract_eml_attachment(raw_email)

            if eml_attachment:
                logger.info("Processing .eml attachment - extracting original email data with full headers")

                # Parse the .eml file
                original_msg = BytesParser(policy=policy.default).parsebytes(eml_attachment)

                # Extract all data from original email
                from_header = original_msg.get('From', '')
                from_name, from_address = parseaddr(from_header)

                result = {
                    'is_forwarded': True,
                    'has_eml_attachment': True,
                    'original_from_name': from_name,
                    'original_from_address': from_address,
                    'original_subject': original_msg.get('Subject', ''),
                    'original_date': self._parse_date(original_msg.get('Date')),
                    'original_to': original_msg.get('To', ''),
                    'original_message_id': original_msg.get('Message-ID', ''),
                    'original_raw_email': eml_attachment,  # Save raw email for DKIM/SPF validation
                    'original_headers': dict(original_msg.items()),
                    'original_received_headers': self._parse_received_headers(original_msg),
                    'original_sender_ip': self._extract_sender_ip(original_msg),
                    'original_return_path': original_msg.get('Return-Path', ''),
                    'original_reply_to': original_msg.get('Reply-To', ''),
                    'original_authentication_results': self.parse_authentication_results(original_msg),
                }

                logger.info(f"Extracted .eml attachment from: {from_address}")
                return result

            # Fallback to old text-based parsing
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            body_text = self._get_body(msg, 'plain')
            body_html = self._get_body(msg, 'html')

            # Combine both text and HTML for better extraction
            combined_body = body_text + '\n' + body_html

            # Look for forwarded message markers
            forwarded_patterns = [
                r'---------- Forwarded message ---------',
                r'-------- Original Message --------',
                r'Begin forwarded message:',
                r'Forwarded Message',
                r'Исходное сообщение',  # Russian
            ]

            is_forwarded = any(re.search(pattern, combined_body, re.IGNORECASE) for pattern in forwarded_patterns)

            if not is_forwarded:
                return None

            logger.info("Detected forwarded email (text-based), extracting original sender...")

            # Find the forwarded message section (after the marker)
            forwarded_section_match = re.search(
                r'[-]{10}\s*Forwarded message\s*[-]{9}(.*?)(?=\r?\n\r?\n[A-Z]|\Z)',
                body_text,
                re.DOTALL | re.IGNORECASE
            )

            if not forwarded_section_match:
                # Try alternative patterns
                forwarded_section_match = re.search(
                    r'((?:From|От|Date|Subject|To|Cc):.*?)(?=\r?\n\r?\n[^\s:]|\Z)',
                    body_text,
                    re.DOTALL
                )

            if forwarded_section_match:
                forwarded_content = forwarded_section_match.group(1) if len(forwarded_section_match.groups()) > 0 else forwarded_section_match.group(0)
            else:
                forwarded_content = body_text

            # Extract From: field from forwarded content (support different languages)
            # Patterns for From: in different languages
            from_patterns = [
                r'(?:From|От):\s*([^\n<]+<[^>]+>)',  # Name <email@example.com>
                r'(?:From|От):\s*([^\n]+)',  # Just email or name
            ]

            from_match = None
            for pattern in from_patterns:
                from_match = re.search(pattern, forwarded_content, re.MULTILINE)
                if from_match:
                    break

            # Extract other fields
            subject_patterns = [r'(?:Subject|Тема):\s*([^\n]+)']
            date_patterns = [r'(?:Date|Дата):\s*([^\n]+)']
            to_patterns = [r'(?:To|Кому):\s*([^\n]+)']

            subject_match = None
            for pattern in subject_patterns:
                subject_match = re.search(pattern, forwarded_content, re.MULTILINE)
                if subject_match:
                    break

            date_match = None
            for pattern in date_patterns:
                date_match = re.search(pattern, forwarded_content, re.MULTILINE)
                if date_match:
                    break

            to_match = None
            for pattern in to_patterns:
                to_match = re.search(pattern, forwarded_content, re.MULTILINE)
                if to_match:
                    break

            if from_match:
                from_header = from_match.group(1).strip()
                from_name, from_address = parseaddr(from_header)

                result = {
                    'is_forwarded': True,
                    'has_eml_attachment': False,
                    'original_from_name': from_name,
                    'original_from_address': from_address,
                    'original_subject': subject_match.group(1).strip() if subject_match else None,
                    'original_date': date_match.group(1).strip() if date_match else None,
                    'original_to': to_match.group(1).strip() if to_match else None,
                    'forwarded_body': body_text
                }

                logger.info(f"Extracted forwarded email from text: {from_address}")
                return result

            return None

        except Exception as e:
            logger.error(f"Failed to extract forwarded email: {e}")
            return None

    def extract_attachments(self, raw_email: bytes, save_dir: str) -> List[Dict[str, Any]]:
        """
        Extract all attachments from email (except .eml files)

        Args:
            raw_email: Raw email bytes
            save_dir: Directory to save attachments

        Returns:
            List of attachment info dictionaries
        """
        import os
        attachments = []

        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)

            if not msg.is_multipart():
                return attachments

            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue

                filename = part.get_filename()
                if not filename:
                    continue

                # Skip .eml files (we handle them separately)
                if filename.lower().endswith('.eml'):
                    continue

                # Sanitize filename to prevent path traversal
                filename = os.path.basename(filename)
                filename = re.sub(r'[^\w\.\-]', '_', filename)
                if not filename:
                    continue

                # Save attachment
                file_path = os.path.join(save_dir, filename)
                with open(file_path, 'wb') as f:
                    f.write(part.get_payload(decode=True))

                attachments.append({
                    'filename': filename,
                    'filepath': file_path,
                    'content_type': part.get_content_type(),
                    'size': len(part.get_payload(decode=True))
                })

                logger.info(f"Extracted attachment: {filename} ({part.get_content_type()})")

        except Exception as e:
            logger.error(f"Failed to extract attachments: {e}")

        return attachments

    def extract_urls(self, raw_email: bytes) -> List[str]:
        """
        Extract all URLs from email body

        Args:
            raw_email: Raw email bytes

        Returns:
            List of unique URLs found in email
        """
        urls = set()

        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)

            # Extract from text/plain parts
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    try:
                        text = part.get_content()
                        # Find URLs in text
                        found_urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
                        urls.update(found_urls)
                    except:
                        pass

                elif part.get_content_type() == 'text/html':
                    try:
                        html = part.get_content()
                        # Find URLs in href attributes
                        found_urls = re.findall(r'href=["\']?(https?://[^"\'>\s]+)["\']?', html, re.IGNORECASE)
                        urls.update(found_urls)
                        # Also find plain URLs in HTML
                        found_urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', html)
                        urls.update(found_urls)
                    except:
                        pass

            logger.info(f"Extracted {len(urls)} unique URLs from email")

        except Exception as e:
            logger.error(f"Failed to extract URLs: {e}")

        return list(urls)

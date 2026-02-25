import os
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

from src.analyzers.email_parser import EmailParser
from src.analyzers.domain_analyzer import DomainAnalyzer
from src.analyzers.ip_analyzer import IPAnalyzer
from src.analyzers.website_analyzer import WebsiteAnalyzer
from src.analyzers.osint_analyzer import OSINTAnalyzer
from src.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from src.services.claude_service import ClaudeService
from src.services.openai_service import OpenAIService
from src.services.perplexity_service import PerplexityService
from src.services.pdf_generator_unicode import PDFGenerator
from src.services.email_service import EmailService
from src.utils.database import db, EmailCheck, CheckResult, StatusEnum, RiskLevelEnum
from src.utils.logger import logger
from config.config import config


class Orchestrator:
    """Main orchestrator for email analysis workflow"""

    def __init__(self):
        self.email_parser = EmailParser()
        self.domain_analyzer = DomainAnalyzer()
        self.ip_analyzer = IPAnalyzer()
        self.website_analyzer = WebsiteAnalyzer()
        self.osint_analyzer = OSINTAnalyzer()
        self.virustotal_analyzer = VirusTotalAnalyzer()

        # Initialize AI service based on configuration
        if config.AI_PROVIDER == 'openai':
            self.ai_service = OpenAIService()
            logger.info("Using OpenAI API for analysis")
        elif config.AI_PROVIDER == 'perplexity':
            self.ai_service = PerplexityService()
            logger.info("Using Perplexity API for analysis")
        else:
            self.ai_service = ClaudeService()
            logger.info("Using Claude API for analysis")

        self.pdf_generator = PDFGenerator()
        self.email_service = EmailService()

    def process_email(self, message_id: str, raw_email: bytes) -> bool:
        """
        Process a single email through complete analysis pipeline

        Args:
            message_id: Email message ID
            raw_email: Raw email bytes

        Returns:
            True if successful, False otherwise
        """
        session = db.get_session()

        try:
            # Check if email already exists
            existing_check = session.query(EmailCheck).filter_by(message_id=message_id).first()
            if existing_check:
                # Reuse existing record for recheck
                logger.info(f"Email {message_id} already exists (ID: {existing_check.id}), running recheck...")
                check = existing_check

                # Delete old results
                session.query(CheckResult).filter_by(check_id=check.id).delete()

                # Reset status
                check.status = StatusEnum.PROCESSING
                check.overall_score = 0
                check.risk_level = None
                session.commit()
            else:
                # Create new record
                check = None

            logger.info(f"Starting analysis for email: {message_id}")

            # Step 1: Check if there's an .eml attachment first
            forwarded_data = self.email_parser.extract_forwarded_email(raw_email)

            if forwarded_data and forwarded_data.get('has_eml_attachment'):
                # PRIORITY: If .eml attachment exists, analyze ONLY it, not the wrapper
                logger.info("Found .eml attachment - analyzing ONLY the original email, not the wrapper")

                # Parse the ORIGINAL email from .eml attachment
                email_data = self.email_parser.parse_email(forwarded_data['original_raw_email'])

                # Store wrapper info for reply purposes
                wrapper_data = self.email_parser.parse_email(raw_email)
                email_data['is_forwarded'] = True
                email_data['has_eml_attachment'] = True
                email_data['forwarder_address'] = wrapper_data.get('from_address')
                email_data['forwarder_name'] = wrapper_data.get('from_name')

                # Use data from .eml
                email_data['original_raw_email'] = forwarded_data.get('original_raw_email')
                email_data['original_headers'] = forwarded_data.get('original_headers')
                email_data['original_received_headers'] = forwarded_data.get('original_received_headers')
                email_data['original_sender_ip'] = forwarded_data.get('original_sender_ip')
                email_data['original_authentication_results'] = forwarded_data.get('original_authentication_results')

                logger.info(f"Analyzing original email from .eml: from={email_data.get('from_address')}, subject={email_data.get('subject')}, IP={email_data.get('original_sender_ip')}")

            elif forwarded_data and not forwarded_data.get('has_eml_attachment'):
                # Fallback: Parse from text (old method)
                logger.info("No .eml attachment found - using text-based parsing (less accurate)")
                email_data = self.email_parser.parse_email(raw_email)

                forwarder_address = email_data.get('from_address')
                forwarder_name = email_data.get('from_name')

                # Override with forwarded email data from text
                email_data['from_address'] = forwarded_data['original_from_address']
                email_data['from_name'] = forwarded_data['original_from_name']
                email_data['subject'] = forwarded_data['original_subject'] or email_data['subject']
                email_data['is_forwarded'] = True
                email_data['has_eml_attachment'] = False
                email_data['forwarder_address'] = forwarder_address
                email_data['forwarder_name'] = forwarder_name

                logger.info(f"Extracted from text: from={email_data.get('from_address')}")
            else:
                # Regular email - not forwarded
                logger.info("Regular email (not forwarded) - analyzing as-is")
                email_data = self.email_parser.parse_email(raw_email)
                email_data['is_forwarded'] = False
                email_data['has_eml_attachment'] = False

            # Step 2: Create or update database record
            if not check:
                # Create new record
                check = EmailCheck(
                    message_id=message_id,
                    subject=email_data.get('subject'),
                    from_address=email_data.get('from_address'),
                    from_name=email_data.get('from_name'),
                    to_address=email_data.get('to_address'),
                    received_date=email_data.get('date'),
                    status=StatusEnum.PROCESSING
                )
                session.add(check)
                session.commit()
            else:
                # Update existing record
                check.subject = email_data.get('subject')
                check.from_address = email_data.get('from_address')
                check.from_name = email_data.get('from_name')
                check.to_address = email_data.get('to_address')
                check.received_date = email_data.get('date')
                session.commit()

            # Save raw email (wrapper)
            raw_email_path = self._save_raw_email(message_id, raw_email)
            check.raw_email_path = raw_email_path

            # Save original .eml if available
            if email_data.get('has_eml_attachment') and email_data.get('original_raw_email'):
                original_eml_path = self._save_raw_email(f"{message_id}_original", email_data.get('original_raw_email'))
                logger.info(f"Saved original .eml file: {original_eml_path}")
                email_data['original_eml_path'] = original_eml_path

            session.commit()

            # Step 3: Run all analyses
            # IMPORTANT: If we have .eml attachment, use its raw data for analysis
            if email_data.get('has_eml_attachment') and email_data.get('original_raw_email'):
                logger.info("Using original raw email from .eml for analysis")
                analysis_data = self._run_analyses(email_data, email_data.get('original_raw_email'))
            else:
                analysis_data = self._run_analyses(email_data, raw_email)

            # Step 4: AI analysis (OpenAI, Claude, or Perplexity)
            ai_result = self.ai_service.analyze_email_security(analysis_data)

            logger.info(f"AI result keys: {ai_result.keys()}")
            logger.info(f"AI full_analysis length: {len(ai_result.get('full_analysis') or '')}")
            analysis_data.update(ai_result)

            # Add AI provider info for PDF report
            analysis_data['ai_provider'] = config.AI_PROVIDER

            # Step 5: Calculate overall score
            overall_score = self._calculate_overall_score(analysis_data)
            analysis_data['overall_score'] = overall_score

            # Determine risk level
            risk_level = self._determine_risk_level(overall_score, ai_result.get('risk_level'))
            analysis_data['risk_level'] = risk_level

            # Step 6: Save results to database
            self._save_results(session, check.id, analysis_data)

            # Update check record
            check.overall_score = overall_score
            check.risk_level = RiskLevelEnum(risk_level)
            check.status = StatusEnum.COMPLETED
            session.commit()

            # Step 7: Generate PDF report
            pdf_path = self._generate_pdf_report(check.id, analysis_data)
            check.report_pdf_path = pdf_path
            session.commit()

            # Step 8: Send email response
            self._send_email_response(email_data, analysis_data, pdf_path, raw_email_path)

            logger.info(f"Analysis completed successfully for: {message_id}")
            return True

        except Exception as e:
            import traceback
            logger.error(f"Failed to process email {message_id}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")

            if 'check' in locals():
                check.status = StatusEnum.FAILED
                session.commit()

            return False

        finally:
            session.close()

    def _run_analyses(self, email_data: Dict[str, Any], raw_email: bytes) -> Dict[str, Any]:
        """
        Run all analysis modules

        Args:
            email_data: Parsed email data (already contains data from .eml if present)
            raw_email: Raw email bytes (MUST be from .eml if has_eml_attachment=True)
        """
        analysis = {}

        # Extract domain and IP
        from_address = email_data.get('from_address', '')
        domain = from_address.split('@')[-1] if '@' in from_address else ''

        # Mark if using .eml and get correct sender IP and authentication results
        if email_data.get('has_eml_attachment'):
            analysis['used_eml_attachment'] = True
            analysis['original_headers'] = email_data.get('original_headers')
            analysis['original_received_headers'] = email_data.get('original_received_headers')
            # IMPORTANT: Use original_sender_ip from .eml, NOT from wrapper
            sender_ip = email_data.get('original_sender_ip', '')
            # IMPORTANT: Use original_authentication_results from .eml
            auth_results_source = email_data.get('original_authentication_results', {})
            logger.info(f"Using .eml attachment data for ALL checks - sender IP from original: {sender_ip}")
        else:
            analysis['used_eml_attachment'] = False
            sender_ip = email_data.get('sender_ip', '')
            auth_results_source = email_data.get('authentication_results', {})
            logger.info(f"Using regular email for authentication checks - sender IP: {sender_ip}")

        # DKIM/SPF/DMARC validation
        # Priority: Use Authentication-Results from Gmail if available (already validated)
        # Fallback: Perform our own validation
        auth_results = auth_results_source

        # Check if we have valid results from Gmail Authentication-Results
        gmail_spf_result = auth_results.get('spf', {}).get('result', 'none')
        gmail_dkim_result = auth_results.get('dkim', {}).get('result', 'none')
        gmail_dmarc_result = auth_results.get('dmarc', {}).get('result', 'none')

        if gmail_spf_result != 'none' or gmail_dkim_result != 'none' or gmail_dmarc_result != 'none':
            logger.info("Using Authentication-Results from Gmail (already validated by receiving server)")

            # Use Gmail's SPF result
            if gmail_spf_result != 'none':
                analysis['spf'] = {
                    'valid': gmail_spf_result == 'pass',
                    'result': gmail_spf_result,
                    'sender_ip': auth_results['spf']['details'].get('sender_ip', sender_ip),
                    'domain': auth_results['spf']['details'].get('domain', domain),
                    'source': 'gmail_authentication_results'
                }
                logger.info(f"SPF result from Gmail: {gmail_spf_result}")

            # Use Gmail's DKIM result
            if gmail_dkim_result != 'none':
                analysis['dkim'] = {
                    'valid': gmail_dkim_result == 'pass',
                    'signature_present': gmail_dkim_result in ['pass', 'fail'],
                    'details': auth_results['dkim']['details'],
                    'result': gmail_dkim_result,
                    'source': 'gmail_authentication_results'
                }
                logger.info(f"DKIM result from Gmail: {gmail_dkim_result}")

            # Use Gmail's DMARC result (even if 'none')
            # Note: 'none' means the receiving server didn't perform DMARC check
            analysis['dmarc'] = {
                'valid': gmail_dmarc_result == 'pass',
                'result': gmail_dmarc_result,
                'policy': auth_results['dmarc']['details'].get('policy', 'unknown'),
                'source': 'gmail_authentication_results',
                'checked': gmail_dmarc_result != 'none'  # Whether DMARC was actually checked
            }
            logger.info(f"DMARC result from Gmail: {gmail_dmarc_result}")
        else:
            # Fallback to our own validation
            logger.info("No Gmail Authentication-Results found - running our own validation checks...")
            analysis['dkim'] = self.email_parser.validate_dkim(raw_email)
            if sender_ip and domain:
                analysis['spf'] = self.email_parser.validate_spf(sender_ip, domain)
            else:
                logger.warning(f"Missing sender_ip or domain for SPF check: ip={sender_ip}, domain={domain}")
            analysis['dmarc'] = self.email_parser.validate_dmarc(domain)

        # Domain analysis
        if domain:
            logger.info(f"Analyzing domain: {domain}")
            domain_info = self.domain_analyzer.analyze_domain(domain) or {}
            analysis.update({
                'domain': domain,
                'domain_age_days': domain_info.get('age_days'),
                'registrar': domain_info.get('registrar'),
                'whois': domain_info.get('whois'),
                'mx_records': domain_info.get('mx_records'),
                'dns_records': domain_info.get('dns')
            })

        # IP analysis
        if sender_ip:
            logger.info(f"Analyzing IP: {sender_ip}")
            ip_info = self.ip_analyzer.analyze_ip(sender_ip) or {}

            # Safe extraction with proper None handling
            blacklist_info = ip_info.get('blacklist_status') or {}
            proxy_info = ip_info.get('is_proxy') or {}

            analysis.update({
                'sender_ip': sender_ip,
                'ip_location': ip_info.get('geolocation'),
                'ip_blacklisted': blacklist_info.get('blacklisted'),
                'blacklist_count': blacklist_info.get('blacklist_count', 0),
                'is_proxy': proxy_info.get('is_proxy')
            })

        # Website analysis
        if domain:
            logger.info(f"Analyzing website: {domain}")
            website_info = self.website_analyzer.analyze_website(domain) or {}

            # Safe extraction with proper None handling
            ssl_info = website_info.get('ssl') or {}
            tech_info = website_info.get('technologies') or {}

            analysis.update({
                'website_exists': website_info.get('exists'),
                'https_accessible': website_info.get('https_accessible'),
                'ssl_valid': ssl_info.get('valid'),
                'ssl_days_left': ssl_info.get('days_until_expiry'),
                'cms': tech_info.get('cms')
            })

        # OSINT analysis
        if from_address:
            logger.info(f"Running OSINT for: {from_address}")
            osint_info = self.osint_analyzer.analyze_email(from_address) or {}

            # Safely extract OSINT data with proper None handling
            breach_data = osint_info.get('breach_data') or {}
            social_profiles = osint_info.get('social_profiles') or {}
            email_validation = osint_info.get('email_validation') or {}

            analysis.update({
                'email_in_breaches': breach_data.get('found_in_breaches'),
                'social_profiles_found': social_profiles.get('found'),
                'is_disposable': email_validation.get('is_disposable'),
                'is_free_provider': email_validation.get('is_free_provider')
            })

        # VirusTotal analysis (attachments and URLs)
        if config.VIRUSTOTAL_API_KEY:
            logger.info("Running VirusTotal analysis on attachments and URLs")

            # Extract and scan attachments
            attachment_dir = os.path.join(config.ATTACHMENTS_DIR, email_data.get('message_id', 'unknown'))
            os.makedirs(attachment_dir, exist_ok=True)

            attachments = self.email_parser.extract_attachments(raw_email, attachment_dir)
            attachment_results = []

            for attachment in attachments:
                result = self.virustotal_analyzer.analyze_file(
                    attachment['filepath'],
                    attachment['filename']
                )
                attachment_results.append(result)
                logger.info(f"VirusTotal scan for {attachment['filename']}: {result.get('detections', 0)} detections")

            # Extract and scan URLs
            urls = self.email_parser.extract_urls(raw_email)
            url_results = []

            # Limit URL scanning to first 10 URLs to avoid API limits
            for url in urls[:10]:
                result = self.virustotal_analyzer.analyze_url(url)
                url_results.append(result)
                logger.info(f"VirusTotal scan for {url}: {result.get('detections', 0)} detections")

            analysis.update({
                'virustotal_attachments': attachment_results,
                'virustotal_urls': url_results,
                'virustotal_enabled': True
            })
        else:
            analysis.update({
                'virustotal_enabled': False
            })

        # Add email data
        analysis.update({
            'from_address': email_data.get('from_address'),
            'from_name': email_data.get('from_name'),
            'to_address': email_data.get('to_address'),
            'subject': email_data.get('subject'),
            'date': email_data.get('date'),
            'message_id': email_data.get('message_id')
        })

        return analysis

    def _calculate_overall_score(self, data: Dict[str, Any]) -> int:
        """Calculate overall trust score (0-100)"""
        score = 100

        # Authentication (40 points)
        if not data.get('dkim', {}).get('valid'):
            score -= 15
        if not data.get('spf', {}).get('valid'):
            score -= 15
        if not data.get('dmarc', {}).get('valid'):
            score -= 10

        # Domain (20 points)
        domain_age = data.get('domain_age_days')
        if domain_age is not None:
            if domain_age < 30:
                score -= 15
            elif domain_age < 365:
                score -= 5

        # IP (20 points)
        if data.get('ip_blacklisted'):
            score -= 20
        if data.get('is_proxy'):
            score -= 10

        # Website (10 points)
        if not data.get('website_exists'):
            score -= 5
        if not data.get('ssl_valid'):
            score -= 5

        # OSINT (10 points)
        if data.get('email_in_breaches'):
            score -= 5
        if data.get('is_disposable'):
            score -= 5

        return max(0, min(100, score))

    def _determine_risk_level(self, score: int, ai_risk: str) -> str:
        """Determine final risk level"""
        # Trust AI's assessment primarily
        if ai_risk in ['green', 'yellow', 'red']:
            return ai_risk

        # Fallback to score-based
        if score >= config.RISK_GREEN_THRESHOLD:
            return 'green'
        elif score >= config.RISK_YELLOW_THRESHOLD:
            return 'yellow'
        else:
            return 'red'

    def _save_results(self, session, check_id: int, data: Dict[str, Any]):
        """Save analysis results to database"""
        result = CheckResult(
            check_id=check_id,
            dkim_valid=data.get('dkim', {}).get('valid'),
            dkim_details=data.get('dkim'),
            spf_valid=data.get('spf', {}).get('valid'),
            spf_details=data.get('spf'),
            dmarc_valid=data.get('dmarc', {}).get('valid'),
            dmarc_details=data.get('dmarc'),
            domain_whois=data.get('whois'),
            domain_age_days=data.get('domain_age_days'),
            domain_registrar=data.get('registrar'),
            mx_records=data.get('mx_records'),
            dns_records=data.get('dns_records'),
            sender_ip=data.get('sender_ip'),
            ip_location=data.get('ip_location'),
            ip_blacklisted=data.get('ip_blacklisted'),
            ip_blacklist_details={'count': data.get('blacklist_count', 0)},
            website_exists=data.get('website_exists'),
            website_ssl_valid=data.get('ssl_valid'),
            website_ssl_details={'days_left': data.get('ssl_days_left')},
            email_in_breaches=data.get('email_in_breaches'),
            claude_analysis=data.get('full_analysis'),  # Note: field name kept for backward compatibility
            claude_verdict=data.get('verdict')  # Note: field name kept for backward compatibility
        )
        session.add(result)
        session.commit()

    def _save_raw_email(self, message_id: str, raw_email: bytes) -> str:
        """Save raw email to file"""
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{message_id[:20]}.eml"
        filepath = os.path.join(config.ATTACHMENTS_DIR, filename)
        Path(config.ATTACHMENTS_DIR).mkdir(parents=True, exist_ok=True)

        with open(filepath, 'wb') as f:
            f.write(raw_email)

        return filepath

    def _generate_pdf_report(self, check_id: int, data: Dict[str, Any]) -> str:
        """Generate PDF report"""
        filename = f"report_{check_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(config.REPORTS_DIR, filename)
        Path(config.REPORTS_DIR).mkdir(parents=True, exist_ok=True)

        self.pdf_generator.generate_report(data, filepath)
        return filepath

    def _send_email_response(self, email_data: Dict, analysis: Dict, pdf_path: str, eml_path: str):
        """Send email response with report"""
        # If this is a forwarded email, send to the forwarder, not the original sender
        if email_data.get('is_forwarded') and email_data.get('forwarder_address'):
            reply_to = email_data.get('forwarder_address')
            logger.info(f"Sending report to forwarder: {reply_to}")
        else:
            reply_to = email_data.get('from_address')
            logger.info(f"Sending report to sender: {reply_to}")

        subject = f"Проверка: {email_data.get('subject', 'Email Check')}"

        body = self.ai_service.generate_summary(analysis, config.REPORT_LANGUAGE)

        self.email_service.send_report(
            to_address=reply_to,
            subject=subject,
            body=body,
            pdf_path=pdf_path,
            original_email_path=eml_path
        )

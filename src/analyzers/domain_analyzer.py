import whois
import dns.resolver
import requests
import unicodedata
from datetime import datetime
from typing import Dict, Any, List, Optional
from src.utils.logger import logger
from src.analyzers.ccTLD_whois import ccTLDWhoisChecker
from src.analyzers.data.email_lists import DISPOSABLE_DOMAINS
from config.config import config


class DomainAnalyzer:
    """Analyze domain information and reputation"""

    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
        self.cctld_checker = ccTLDWhoisChecker()
        self.api_ninjas_key = config.API_NINJAS_API_KEY

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive domain analysis

        Args:
            domain: Domain name to analyze

        Returns:
            Dictionary with domain analysis results
        """
        result = {
            'domain': domain,
            'whois': self.get_whois_info(domain),
            'dns': self.get_dns_records(domain),
            'mx_records': self.get_mx_records(domain),
            'age_days': None,
            'registrar': None,
            'reputation': self.check_domain_reputation(domain)
        }

        # Calculate domain age
        if result['whois'] and result['whois'].get('creation_date'):
            creation_date = result['whois']['creation_date']
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            # Handle both datetime objects and ISO format strings
            if isinstance(creation_date, datetime):
                age = datetime.now() - creation_date
                result['age_days'] = age.days
            elif isinstance(creation_date, str):
                try:
                    # Parse ISO format string
                    creation_dt = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                    age = datetime.now() - creation_dt
                    result['age_days'] = age.days
                except (ValueError, AttributeError):
                    pass

        # Extract registrar
        if result['whois'] and result['whois'].get('registrar'):
            result['registrar'] = result['whois']['registrar']

        logger.info(f"Domain analysis completed for {domain}")
        return result

    def get_whois_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get WHOIS information for domain
        First tries API Ninjas, then ccTLD-specific checkers, then falls back to standard whois

        Args:
            domain: Domain name

        Returns:
            Dictionary with WHOIS data
        """
        # First try API Ninjas if key is available
        if self.api_ninjas_key:
            try:
                response = requests.get(
                    f'https://api.api-ninjas.com/v1/whois?domain={domain}',
                    headers={'X-Api-Key': self.api_ninjas_key},
                    timeout=10
                )

                if response.status_code == 200:
                    data = response.json()

                    # Helper function to extract timestamp and convert to ISO string
                    def parse_timestamp(value):
                        if not value:
                            return None
                        if isinstance(value, list):
                            value = value[0] if value else None
                        if value:
                            try:
                                dt = datetime.fromtimestamp(int(value))
                                # Return ISO format string for JSON serialization
                                return dt.isoformat()
                            except (ValueError, TypeError):
                                return None
                        return None

                    # Convert Unix timestamps to ISO format strings (JSON-serializable)
                    whois_data = {
                        'domain_name': data.get('domain_name'),
                        'registrar': data.get('registrar'),
                        'creation_date': parse_timestamp(data.get('creation_date')),
                        'expiration_date': parse_timestamp(data.get('expiration_date')),
                        'updated_date': parse_timestamp(data.get('updated_date')),
                        'name_servers': data.get('name_servers'),
                        'whois_server': data.get('whois_server'),
                        'status': None,
                        'emails': None,
                        'org': None,
                        'country': None,
                    }

                    logger.info(f"WHOIS info retrieved for {domain} via API Ninjas")
                    return whois_data
                else:
                    logger.warning(f"API Ninjas returned status {response.status_code} for {domain}")

            except Exception as e:
                logger.warning(f"API Ninjas WHOIS failed for {domain}: {e}")

        # Second, try ccTLD checker for country domains
        try:
            cctld_data = self.cctld_checker.check_domain(domain)
            if cctld_data:
                logger.info(f"WHOIS info retrieved for {domain} via ccTLD checker")

                # Parse dates if they're in string format
                whois_data = cctld_data.copy()
                if 'creation_date' in whois_data and whois_data['creation_date']:
                    try:
                        # Try to parse Spanish date format: DD-MM-YYYY
                        date_str = whois_data['creation_date']
                        if '-' in date_str and len(date_str.split('-')[0]) == 2:
                            whois_data['creation_date'] = datetime.strptime(date_str, '%d-%m-%Y')
                    except:
                        pass

                return whois_data
        except Exception as e:
            logger.debug(f"ccTLD checker failed for {domain}: {e}")

        # Fallback to standard whois
        try:
            w = whois.whois(domain)

            whois_data = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'updated_date': w.updated_date,
                'status': w.status,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'country': w.country,
            }

            # Convert datetime objects to strings for JSON serialization
            for key, value in whois_data.items():
                if isinstance(value, datetime):
                    whois_data[key] = value.isoformat()
                elif isinstance(value, list) and value and isinstance(value[0], datetime):
                    whois_data[key] = [v.isoformat() if isinstance(v, datetime) else v for v in value]

            logger.info(f"WHOIS info retrieved for {domain}")
            return whois_data

        except Exception as e:
            logger.warning(f"Failed to get WHOIS info for {domain}: {e}")
            return None

    def get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """
        Get various DNS records for domain

        Args:
            domain: Domain name

        Returns:
            Dictionary with DNS records
        """
        records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'TXT': [],
            'NS': [],
            'CNAME': []
        }

        for record_type in records.keys():
            try:
                answers = self.dns_resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                logger.warning(f"Domain {domain} does not exist")
                break
            except Exception as e:
                logger.debug(f"Failed to get {record_type} record for {domain}: {e}")

        return records

    def get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get MX records with priority

        Args:
            domain: Domain name

        Returns:
            List of MX records with priority
        """
        mx_records = []
        try:
            answers = self.dns_resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })

            # Sort by priority
            mx_records.sort(key=lambda x: x['priority'])
            logger.info(f"Found {len(mx_records)} MX records for {domain}")

        except dns.resolver.NoAnswer:
            logger.warning(f"No MX records found for {domain}")
        except Exception as e:
            logger.error(f"Failed to get MX records for {domain}: {e}")

        return mx_records

    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation using various sources

        Args:
            domain: Domain name

        Returns:
            Dictionary with reputation information
        """
        reputation = {
            'google_safe_browsing': self._check_google_safe_browsing(domain),
            'is_disposable': self._is_disposable_domain(domain),
            'similarity_check': self._check_similar_domains(domain)
        }

        return reputation

    def _check_google_safe_browsing(self, domain: str) -> Dict[str, Any]:
        """
        Check domain against Google Safe Browsing (placeholder)
        Note: Requires Google Safe Browsing API key for production

        Args:
            domain: Domain name

        Returns:
            Dictionary with safe browsing status
        """
        # Placeholder - in production, use actual Google Safe Browsing API
        return {
            'checked': False,
            'safe': None,
            'note': 'Google Safe Browsing API key required'
        }

    def _is_disposable_domain(self, domain: str) -> bool:
        """Check if domain is a known disposable email provider"""
        return domain.lower() in DISPOSABLE_DOMAINS

    def _check_similar_domains(self, domain: str) -> List[str]:
        """Check for typosquatting with expanded detection techniques"""
        similar_domains = []
        base_domain = domain.split('.')[0]
        tld = '.'.join(domain.split('.')[1:])

        # Character substitution (expanded)
        substitutions = {
            'o': ['0'], '0': ['o'], 'l': ['1', 'i'], '1': ['l', 'i'],
            'i': ['1', 'l'], 'e': ['3'], '3': ['e'], 'a': ['4'],
            's': ['5'], '5': ['s'], 'g': ['9', 'q'], '9': ['g'],
            'b': ['d'], 'd': ['b'], 'n': ['m'], 'm': ['n'],
            'w': ['vv'],
        }
        multi_substitutions = {
            'rn': ['m'], 'cl': ['d'], 'nn': ['m'],
        }

        variants = set()

        # 1. Single character substitution
        for i, char in enumerate(base_domain):
            if char in substitutions:
                for sub in substitutions[char]:
                    variant = base_domain[:i] + sub + base_domain[i+1:]
                    variants.add(f"{variant}.{tld}")

        # 2. Multi-character substitution
        for i in range(len(base_domain) - 1):
            pair = base_domain[i:i+2]
            if pair in multi_substitutions:
                for sub in multi_substitutions[pair]:
                    variant = base_domain[:i] + sub + base_domain[i+2:]
                    variants.add(f"{variant}.{tld}")

        # 3. Character omission
        for i in range(len(base_domain)):
            variant = base_domain[:i] + base_domain[i+1:]
            if variant:
                variants.add(f"{variant}.{tld}")

        # 4. Character duplication
        for i in range(len(base_domain)):
            variant = base_domain[:i] + base_domain[i] + base_domain[i:]
            variants.add(f"{variant}.{tld}")

        # 5. Adjacent character swap
        for i in range(len(base_domain) - 1):
            chars = list(base_domain)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            variants.add(f"{''.join(chars)}.{tld}")

        # 6. Alternative TLDs
        for alt_tld in ['com', 'net', 'org', 'info', 'biz', 'co']:
            if alt_tld != tld:
                variants.add(f"{base_domain}.{alt_tld}")

        variants.discard(domain)

        # Check if variants resolve (limit to 15 DNS queries)
        for variant in list(variants)[:15]:
            try:
                self.dns_resolver.resolve(variant, 'A')
                similar_domains.append(variant)
                logger.warning(f"Found similar domain (typosquatting): {variant}")
            except:
                pass

        return similar_domains

    def check_homograph(self, domain: str) -> Dict[str, Any]:
        """Check for IDN homograph attacks (e.g., Cyrillic 'а' instead of Latin 'a')"""
        confusables = {
            '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
            '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u043d': 'h',
            '\u0456': 'i', '\u0458': 'j',
        }

        try:
            domain.encode('ascii')
            has_non_ascii = False
        except UnicodeEncodeError:
            has_non_ascii = True

        is_punycode = 'xn--' in domain.lower()

        confusable_chars = []
        for char in domain.split('.')[0]:
            if char in confusables:
                confusable_chars.append({
                    'char': char,
                    'looks_like': confusables[char],
                    'name': unicodedata.name(char, 'UNKNOWN')
                })

        return {
            'detected': has_non_ascii or is_punycode or len(confusable_chars) > 0,
            'has_non_ascii': has_non_ascii,
            'is_punycode': is_punycode,
            'confusable_chars': confusable_chars[:5],
        }

    def check_spf_record(self, domain: str) -> Dict[str, Any]:
        """
        Check SPF record for domain

        Args:
            domain: Domain name

        Returns:
            Dictionary with SPF record information
        """
        try:
            answers = self.dns_resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    return {
                        'exists': True,
                        'record': txt,
                        'mechanisms': self._parse_spf_mechanisms(txt)
                    }

            return {
                'exists': False,
                'record': None
            }

        except Exception as e:
            logger.error(f"Failed to check SPF record for {domain}: {e}")
            return {
                'exists': False,
                'error': str(e)
            }

    def check_dmarc_record(self, domain: str) -> Dict[str, Any]:
        """
        Check DMARC record for domain

        Args:
            domain: Domain name

        Returns:
            Dictionary with DMARC record information
        """
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.dns_resolver.resolve(dmarc_domain, 'TXT')

            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    return {
                        'exists': True,
                        'record': txt,
                        'policy': self._parse_dmarc_policy(txt)
                    }

            return {
                'exists': False,
                'record': None
            }

        except Exception as e:
            logger.debug(f"No DMARC record found for {domain}: {e}")
            return {
                'exists': False,
                'error': str(e)
            }

    def _parse_spf_mechanisms(self, spf_record: str) -> List[str]:
        """Parse SPF record mechanisms"""
        parts = spf_record.split()
        return [p for p in parts if p.startswith(('ip4:', 'ip6:', 'include:', 'a:', 'mx:', 'all'))]

    def _parse_dmarc_policy(self, dmarc_record: str) -> Dict[str, str]:
        """Parse DMARC policy"""
        policy = {}
        parts = dmarc_record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                policy[key.strip()] = value.strip()
        return policy

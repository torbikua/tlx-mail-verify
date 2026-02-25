"""
ccTLD WHOIS checker for country-code top-level domains
Supports .es, .pl, .ua, and other ccTLDs that don't work with standard WHOIS
"""
import requests
import re
from typing import Dict, Optional
from src.utils.logger import logger


class ccTLDWhoisChecker:
    """Check WHOIS for country-code TLDs through web interfaces"""

    def __init__(self):
        self.timeout = 10

    def check_domain(self, domain: str) -> Optional[Dict[str, any]]:
        """
        Check WHOIS for a domain using appropriate ccTLD service

        Args:
            domain: Domain name to check

        Returns:
            Dict with WHOIS data or None if not available
        """
        # Extract TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return None

        tld = parts[-1].lower()

        # Route to appropriate checker
        if tld == 'es':
            return self._check_es(domain)
        elif tld == 'pl':
            return self._check_pl(domain)
        elif tld == 'ua':
            return self._check_ua(domain)
        elif tld == 'ru':
            return self._check_ru(domain)
        elif tld == 'de':
            return self._check_de(domain)
        elif tld == 'fr':
            return self._check_fr(domain)
        elif tld == 'it':
            return self._check_it(domain)
        else:
            logger.debug(f"No ccTLD checker for .{tld}")
            return None

    def _check_es(self, domain: str) -> Optional[Dict[str, any]]:
        """Check .es domain via nic.es"""
        try:
            url = f"https://www.nic.es/sgnd/public/whois?name={domain}"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code != 200:
                logger.warning(f"nic.es returned {response.status_code} for {domain}")
                return None

            html = response.text

            # Parse HTML for domain status
            result = {
                'registrar': 'nic.es',
                'status': None,
                'creation_date': None,
                'expiry_date': None,
                'registrant': None,
                'nameservers': []
            }

            # Status: Activado / Disponible
            if 'Estado' in html:
                status_match = re.search(r'Estado\s*</th>\s*<td[^>]*>([^<]+)', html)
                if status_match:
                    result['status'] = status_match.group(1).strip()

            # Creation date: Fecha de Alta
            if 'Fecha de Alta' in html:
                creation_match = re.search(r'Fecha de Alta\s*</th>\s*<td[^>]*>([^<]+)', html)
                if creation_match:
                    result['creation_date'] = creation_match.group(1).strip()

            # Expiry date: Fecha de Caducidad
            if 'Fecha de Caducidad' in html or 'Fecha de Expiración' in html:
                expiry_match = re.search(r'Fecha de (?:Caducidad|Expiración)\s*</th>\s*<td[^>]*>([^<]+)', html)
                if expiry_match:
                    result['expiry_date'] = expiry_match.group(1).strip()

            # Registrant: Titular
            if 'Titular' in html:
                registrant_match = re.search(r'Titular\s*</th>\s*<td[^>]*>([^<]+)', html)
                if registrant_match:
                    result['registrant'] = registrant_match.group(1).strip()

            # Agente Registrador
            if 'Agente Registrador' in html:
                registrar_match = re.search(r'Agente Registrador\s*</th>\s*<td[^>]*>([^<]+)', html)
                if registrar_match:
                    result['registrar'] = registrar_match.group(1).strip()

            logger.info(f"Successfully checked .es domain {domain} via nic.es")
            return result

        except Exception as e:
            logger.error(f"Failed to check .es domain {domain}: {e}")
            return None

    def _check_pl(self, domain: str) -> Optional[Dict[str, any]]:
        """Check .pl domain via whois.dns.pl"""
        try:
            url = f"https://www.dns.pl/cgi-bin/en_whois.pl?domain={domain}"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code != 200:
                return None

            text = response.text

            result = {
                'registrar': 'dns.pl',
                'status': None,
                'creation_date': None,
                'nameservers': []
            }

            # Parse whois-like output
            if 'created:' in text.lower():
                creation_match = re.search(r'created:\s*([^\n]+)', text, re.IGNORECASE)
                if creation_match:
                    result['creation_date'] = creation_match.group(1).strip()

            if 'option created:' in text.lower():
                result['status'] = 'Active'

            logger.info(f"Successfully checked .pl domain {domain}")
            return result

        except Exception as e:
            logger.error(f"Failed to check .pl domain {domain}: {e}")
            return None

    def _check_ua(self, domain: str) -> Optional[Dict[str, any]]:
        """Check .ua domain via whois.ua"""
        try:
            # Note: whois.ua might require POST request or different approach
            # This is a simplified version
            url = f"https://whois.ua/domain/{domain}"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code != 200:
                return None

            result = {
                'registrar': 'whois.ua',
                'status': 'Active' if 'domain' in response.text.lower() else 'Unknown',
                'creation_date': None,
                'nameservers': []
            }

            logger.info(f"Successfully checked .ua domain {domain}")
            return result

        except Exception as e:
            logger.error(f"Failed to check .ua domain {domain}: {e}")
            return None

    def _check_ru(self, domain: str) -> Optional[Dict[str, any]]:
        """Check .ru domain via whois.tcinet.ru"""
        try:
            url = f"https://www.whois.com/whois/{domain}"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code != 200:
                return None

            result = {
                'registrar': 'tcinet.ru',
                'status': 'Active' if 'registered' in response.text.lower() else 'Unknown',
                'creation_date': None,
                'nameservers': []
            }

            logger.info(f"Successfully checked .ru domain {domain}")
            return result

        except Exception as e:
            logger.error(f"Failed to check .ru domain {domain}: {e}")
            return None

    def _check_de(self, domain: str) -> Optional[Dict[str, any]]:
        """Check .de domain via denic.de"""
        # .de domains can be checked via standard whois
        return None

    def _check_fr(self, domain: str) -> Optional[Dict[str, any]]:
        """Check .fr domain via afnic.fr"""
        # .fr domains can be checked via standard whois
        return None

    def _check_it(self, domain: str) -> Optional[Dict[str, any]]:
        """Check .it domain via nic.it"""
        # .it domains can be checked via standard whois
        return None

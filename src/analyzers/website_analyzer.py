import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup
from src.utils.logger import logger


class WebsiteAnalyzer:
    """Analyze website information and security"""

    def __init__(self):
        self.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def analyze_website(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive website analysis

        Args:
            domain: Domain name

        Returns:
            Dictionary with website analysis results
        """
        result = {
            'domain': domain,
            'exists': False,
            'http_accessible': False,
            'https_accessible': False,
            'ssl': self.check_ssl(domain),
            'redirects': None,
            'status_code': None,
            'server': None,
            'content_summary': None,
            'technologies': None
        }

        # Try HTTPS first
        https_response = self._try_request(f'https://{domain}')
        if https_response:
            result['exists'] = True
            result['https_accessible'] = True
            result['status_code'] = https_response.status_code
            result['server'] = https_response.headers.get('Server')
            result['redirects'] = self._get_redirect_chain(https_response)
            result['content_summary'] = self._extract_content_summary(https_response)
            result['technologies'] = self._detect_technologies(https_response)

        # Try HTTP as fallback
        if not result['https_accessible']:
            http_response = self._try_request(f'http://{domain}')
            if http_response:
                result['exists'] = True
                result['http_accessible'] = True
                result['status_code'] = http_response.status_code
                result['server'] = http_response.headers.get('Server')
                result['redirects'] = self._get_redirect_chain(http_response)
                result['content_summary'] = self._extract_content_summary(http_response)
                result['technologies'] = self._detect_technologies(http_response)

        logger.info(f"Website analysis completed for {domain}")
        return result

    def check_ssl(self, domain: str) -> Dict[str, Any]:
        """
        Check SSL certificate

        Args:
            domain: Domain name

        Returns:
            Dictionary with SSL information
        """
        ssl_info = {
            'valid': False,
            'exists': False,
            'issuer': None,
            'subject': None,
            'valid_from': None,
            'valid_until': None,
            'days_until_expiry': None,
            'version': None,
            'error': None
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    ssl_info['exists'] = True
                    ssl_info['valid'] = True
                    ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    ssl_info['subject'] = dict(x[0] for x in cert['subject'])
                    ssl_info['version'] = cert.get('version')

                    # Parse dates
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                    ssl_info['valid_from'] = not_before.isoformat()
                    ssl_info['valid_until'] = not_after.isoformat()

                    # Calculate days until expiry
                    days_left = (not_after - datetime.now()).days
                    ssl_info['days_until_expiry'] = days_left

                    if days_left < 0:
                        ssl_info['valid'] = False
                        ssl_info['error'] = 'Certificate expired'
                    elif days_left < 30:
                        logger.warning(f"SSL certificate for {domain} expires in {days_left} days")

                    logger.info(f"SSL certificate valid for {domain}")

        except ssl.SSLError as e:
            ssl_info['error'] = f'SSL Error: {str(e)}'
            logger.warning(f"SSL error for {domain}: {e}")
        except socket.timeout:
            ssl_info['error'] = 'Connection timeout'
        except Exception as e:
            ssl_info['error'] = str(e)
            logger.debug(f"Failed to check SSL for {domain}: {e}")

        return ssl_info

    def _try_request(self, url: str) -> Optional[requests.Response]:
        """Try to make HTTP request"""
        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False  # Allow self-signed certs for testing
            )
            return response
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    def _get_redirect_chain(self, response: requests.Response) -> Optional[list]:
        """Get redirect chain from response"""
        if response.history:
            chain = []
            for r in response.history:
                chain.append({
                    'url': r.url,
                    'status_code': r.status_code
                })
            chain.append({
                'url': response.url,
                'status_code': response.status_code
            })
            return chain
        return None

    def _extract_content_summary(self, response: requests.Response) -> Optional[Dict[str, Any]]:
        """Extract basic content information"""
        try:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Get title
            title = soup.find('title')
            title_text = title.get_text().strip() if title else None

            # Get meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            description = meta_desc.get('content') if meta_desc else None

            # Get h1 tags
            h1_tags = [h1.get_text().strip() for h1 in soup.find_all('h1')[:3]]

            # Check for common elements
            has_forms = bool(soup.find('form'))
            has_login = bool(soup.find(text=lambda x: x and ('login' in x.lower() or 'sign in' in x.lower())))

            # Count links
            links = soup.find_all('a')
            external_links = [a.get('href') for a in links if a.get('href') and a.get('href').startswith('http')]

            return {
                'title': title_text,
                'description': description,
                'h1_tags': h1_tags,
                'has_forms': has_forms,
                'has_login': has_login,
                'total_links': len(links),
                'external_links': len(external_links),
                'content_length': len(response.content)
            }

        except Exception as e:
            logger.debug(f"Failed to extract content summary: {e}")
            return None

    def _detect_technologies(self, response: requests.Response) -> Dict[str, Any]:
        """Detect technologies used on website"""
        technologies = {
            'server': response.headers.get('Server'),
            'x_powered_by': response.headers.get('X-Powered-By'),
            'frameworks': [],
            'cms': None
        }

        try:
            # Check headers
            headers = response.headers

            # Detect common frameworks/CMS from headers
            if 'X-Generator' in headers:
                technologies['cms'] = headers['X-Generator']

            # Check content
            content = response.text.lower()

            # Detect popular CMS
            cms_signatures = {
                'wordpress': ['wp-content', 'wp-includes'],
                'joomla': ['joomla', '/components/'],
                'drupal': ['drupal', '/sites/default/'],
                'magento': ['magento', 'mage/cookies'],
                'shopify': ['shopify', 'cdn.shopify.com']
            }

            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    technologies['cms'] = cms
                    break

            # Detect frameworks
            framework_signatures = {
                'react': ['react', '_react'],
                'angular': ['ng-', 'angular'],
                'vue': ['vue', 'v-'],
                'jquery': ['jquery'],
                'bootstrap': ['bootstrap']
            }

            for framework, signatures in framework_signatures.items():
                if any(sig in content for sig in signatures):
                    technologies['frameworks'].append(framework)

        except Exception as e:
            logger.debug(f"Failed to detect technologies: {e}")

        return technologies

    def check_security_headers(self, domain: str) -> Dict[str, Any]:
        """Check security-related HTTP headers"""
        security_headers = {
            'strict-transport-security': False,
            'x-frame-options': False,
            'x-content-type-options': False,
            'x-xss-protection': False,
            'content-security-policy': False,
            'score': 0
        }

        try:
            response = requests.get(
                f'https://{domain}',
                headers=self.headers,
                timeout=self.timeout,
                verify=False
            )

            headers = response.headers

            if 'Strict-Transport-Security' in headers:
                security_headers['strict-transport-security'] = True
                security_headers['score'] += 20

            if 'X-Frame-Options' in headers:
                security_headers['x-frame-options'] = True
                security_headers['score'] += 20

            if 'X-Content-Type-Options' in headers:
                security_headers['x-content-type-options'] = True
                security_headers['score'] += 20

            if 'X-XSS-Protection' in headers:
                security_headers['x-xss-protection'] = True
                security_headers['score'] += 20

            if 'Content-Security-Policy' in headers:
                security_headers['content-security-policy'] = True
                security_headers['score'] += 20

            logger.info(f"Security headers score for {domain}: {security_headers['score']}/100")

        except Exception as e:
            logger.debug(f"Failed to check security headers for {domain}: {e}")

        return security_headers

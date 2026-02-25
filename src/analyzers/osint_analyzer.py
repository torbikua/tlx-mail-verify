import requests
import re
from typing import Dict, Any, List, Optional
from src.utils.logger import logger


class OSINTAnalyzer:
    """OSINT (Open Source Intelligence) analysis for email addresses"""

    def __init__(self):
        self.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def analyze_email(self, email: str) -> Dict[str, Any]:
        """
        Comprehensive OSINT analysis for email address

        Args:
            email: Email address to analyze

        Returns:
            Dictionary with OSINT results
        """
        result = {
            'email': email,
            'breach_data': self.check_breaches(email),
            'social_profiles': self.find_social_profiles(email),
            'online_mentions': self.search_online_mentions(email),
            'email_validation': self.validate_email_existence(email)
        }

        logger.info(f"OSINT analysis completed for {email}")
        return result

    def check_breaches(self, email: str) -> Dict[str, Any]:
        """
        Check if email appears in known data breaches

        Args:
            email: Email address

        Returns:
            Dictionary with breach information
        """
        # Note: HIBP API requires API key for production use
        # This is a placeholder structure
        breach_info = {
            'checked': False,
            'found_in_breaches': False,
            'breach_count': 0,
            'breaches': [],
            'note': 'HaveIBeenPwned API key required for production'
        }

        try:
            # Placeholder for actual HIBP integration
            # In production, you would need:
            # 1. Register for HIBP API key
            # 2. Use https://haveibeenpwned.com/API/v3
            pass

        except Exception as e:
            logger.error(f"Failed to check breaches for {email}: {e}")
            breach_info['error'] = str(e)

        return breach_info

    def find_social_profiles(self, email: str) -> Dict[str, Any]:
        """
        Search for social media profiles associated with email

        Args:
            email: Email address

        Returns:
            Dictionary with social profiles found
        """
        profiles = {
            'found': False,
            'platforms': {}
        }

        username = email.split('@')[0]

        # Common social platforms to check
        platforms = {
            'github': f'https://github.com/{username}',
            'twitter': f'https://twitter.com/{username}',
            'linkedin': f'https://linkedin.com/in/{username}',
        }

        for platform, url in platforms.items():
            exists = self._check_url_exists(url)
            if exists:
                profiles['found'] = True
                profiles['platforms'][platform] = url
                logger.info(f"Found {platform} profile for {email}")

        return profiles

    def search_online_mentions(self, email: str) -> Dict[str, Any]:
        """
        Search for mentions of email address online

        Args:
            email: Email address

        Returns:
            Dictionary with search results
        """
        mentions = {
            'search_performed': False,
            'mentions_found': False,
            'sources': [],
            'note': 'Limited search without API keys'
        }

        try:
            # Simple Google search simulation (in production, use Google Custom Search API)
            # For now, we'll just mark it as not fully implemented
            mentions['search_performed'] = True

            # In production, you would:
            # 1. Use Google Custom Search API
            # 2. Check paste sites (Pastebin, etc.)
            # 3. Check code repositories (GitHub, GitLab)
            # 4. Check domain-specific sites

        except Exception as e:
            logger.error(f"Failed to search online mentions for {email}: {e}")
            mentions['error'] = str(e)

        return mentions

    def validate_email_existence(self, email: str) -> Dict[str, Any]:
        """
        Validate if email address actually exists (careful - can be detected as spam)

        Args:
            email: Email address

        Returns:
            Dictionary with validation results
        """
        validation = {
            'format_valid': self._validate_email_format(email),
            'domain_exists': False,
            'mailbox_exists': None,  # Requires SMTP verification (risky)
            'is_disposable': self._is_disposable_email(email),
            'is_free_provider': self._is_free_provider(email)
        }

        # Check if domain exists (DNS check)
        domain = email.split('@')[-1]
        validation['domain_exists'] = self._check_domain_exists(domain)

        return validation

    def _check_url_exists(self, url: str) -> bool:
        """Check if URL is accessible"""
        try:
            response = requests.head(
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            return response.status_code == 200
        except:
            return False

    def _validate_email_format(self, email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _check_domain_exists(self, domain: str) -> bool:
        """Check if domain has MX records"""
        try:
            import dns.resolver
            dns.resolver.resolve(domain, 'MX')
            return True
        except:
            return False

    def _is_disposable_email(self, email: str) -> bool:
        """Check if email is from a disposable email provider"""
        domain = email.split('@')[-1].lower()

        disposable_domains = [
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org',
            'fakeinbox.com', 'maildrop.cc', 'yopmail.com',
            'getnada.com', 'trashmail.com', 'sharklasers.com'
        ]

        return domain in disposable_domains

    def _is_free_provider(self, email: str) -> bool:
        """Check if email is from a free email provider"""
        domain = email.split('@')[-1].lower()

        free_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'mail.ru', 'yandex.ru', 'icloud.com', 'aol.com',
            'protonmail.com', 'zoho.com'
        ]

        return domain in free_providers

    def search_linkedin(self, name: str, company: str = None) -> Dict[str, Any]:
        """
        Search for LinkedIn profiles (requires LinkedIn API in production)

        Args:
            name: Person's name
            company: Company name (optional)

        Returns:
            Dictionary with LinkedIn search results
        """
        return {
            'searched': True,
            'found': False,
            'note': 'LinkedIn API integration required for production'
        }

    def check_email_reputation(self, email: str) -> Dict[str, Any]:
        """
        Check email reputation across various sources

        Args:
            email: Email address

        Returns:
            Dictionary with reputation score
        """
        score = 100
        flags = []

        validation = self.validate_email_existence(email)

        # Apply penalties
        if not validation['format_valid']:
            score -= 50
            flags.append('Invalid email format')

        if not validation['domain_exists']:
            score -= 40
            flags.append('Domain does not exist')

        if validation['is_disposable']:
            score -= 30
            flags.append('Disposable email provider')

        # Check breaches
        breach_data = self.check_breaches(email)
        if breach_data.get('found_in_breaches'):
            score -= 20
            flags.append(f"Found in {breach_data['breach_count']} breaches")

        score = max(0, score)

        return {
            'score': score,
            'reputation': 'good' if score >= 70 else 'moderate' if score >= 40 else 'poor',
            'flags': flags
        }

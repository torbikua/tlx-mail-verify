import requests
import socket
import time
from typing import Dict, Any, List, Optional
from src.utils.logger import logger


class IPAnalyzer:
    """Analyze IP address information and reputation"""

    def __init__(self):
        self.timeout = 10
        self._dns_cache = {}
        self._cache_ttl = 3600  # 1 hour

    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Comprehensive IP address analysis

        Args:
            ip_address: IP address to analyze

        Returns:
            Dictionary with IP analysis results
        """
        result = {
            'ip': ip_address,
            'geolocation': self.get_geolocation(ip_address),
            'reverse_dns': self.get_reverse_dns(ip_address),
            'blacklist_status': self.check_blacklists(ip_address),
            'is_proxy': self.check_proxy(ip_address),
            'asn_info': self.get_asn_info(ip_address),
            'detailed_info': self.get_detailed_ip_info(ip_address)  # Детальные флаги для GPT анализа
        }

        logger.info(f"IP analysis completed for {ip_address}")
        return result

    def get_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation information for IP

        Args:
            ip_address: IP address

        Returns:
            Dictionary with geolocation data
        """
        try:
            # Using ip-api.com (free, no key required)
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as')
                    }

                    logger.info(f"Geolocation found for {ip_address}: {geo_data.get('country')}, {geo_data.get('city')}")
                    return geo_data

        except Exception as e:
            logger.error(f"Failed to get geolocation for {ip_address}: {e}")

        return None

    def get_reverse_dns(self, ip_address: str) -> Optional[str]:
        """
        Get reverse DNS (PTR record) for IP

        Args:
            ip_address: IP address

        Returns:
            Hostname or None
        """
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            logger.info(f"Reverse DNS for {ip_address}: {hostname}")
            return hostname
        except Exception as e:
            logger.debug(f"No reverse DNS for {ip_address}: {e}")
            return None

    def check_blacklists(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP against multiple blacklists

        Args:
            ip_address: IP address

        Returns:
            Dictionary with blacklist check results
        """
        # DNS-based blacklists (expanded from 5 to 15)
        blacklists = [
            # Tier 1: Most reliable
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org',
            # Tier 2: Good reputation
            'dnsbl.sorbs.net',
            'cbl.abuseat.org',
            'dnsbl-1.uceprotect.net',
            'psbl.surriel.com',
            'db.wpbl.info',
            # Tier 3: Additional coverage
            'all.s5h.net',
            'bl.mailspike.net',
            'dnsbl.dronebl.org',
            'spam.dnsbl.anonmails.de',
            'dnsbl.spfbl.net',
            'combined.abuse.ch',
            'spam.abuse.ch',
        ]

        results = {}
        blacklisted_count = 0

        for bl in blacklists:
            is_listed = self._check_single_blacklist(ip_address, bl)
            results[bl] = is_listed
            if is_listed:
                blacklisted_count += 1

        return {
            'blacklisted': blacklisted_count > 0,
            'blacklist_count': blacklisted_count,
            'total_checked': len(blacklists),
            'details': results
        }

    def _cached_dns_lookup(self, query: str) -> bool:
        """DNS lookup with TTL-based caching"""
        now = time.time()
        if query in self._dns_cache:
            result, timestamp = self._dns_cache[query]
            if now - timestamp < self._cache_ttl:
                return result

        try:
            socket.gethostbyname(query)
            self._dns_cache[query] = (True, now)
            return True
        except socket.gaierror:
            self._dns_cache[query] = (False, now)
            return False
        except Exception:
            return False

    def _check_single_blacklist(self, ip_address: str, blacklist: str) -> bool:
        """
        Check IP against a single DNSBL (with caching)

        Args:
            ip_address: IP address
            blacklist: Blacklist hostname

        Returns:
            True if blacklisted, False otherwise
        """
        try:
            reversed_ip = '.'.join(reversed(ip_address.split('.')))
            query = f"{reversed_ip}.{blacklist}"

            is_listed = self._cached_dns_lookup(query)
            if is_listed:
                logger.warning(f"IP {ip_address} found in blacklist: {blacklist}")
            return is_listed

        except Exception as e:
            logger.debug(f"Error checking blacklist {blacklist} for {ip_address}: {e}")
            return False

    def check_proxy(self, ip_address: str) -> Dict[str, Any]:
        """
        Check if IP is a known proxy/VPN

        Args:
            ip_address: IP address

        Returns:
            Dictionary with proxy check results
        """
        # Using proxycheck.io (free tier available)
        try:
            response = requests.get(
                f'http://proxycheck.io/v2/{ip_address}?vpn=1&asn=1',
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                if ip_address in data:
                    ip_data = data[ip_address]

                    return {
                        'is_proxy': ip_data.get('proxy') == 'yes',
                        'proxy_type': ip_data.get('type'),
                        'is_vpn': ip_data.get('vpn', False),
                        'risk_score': ip_data.get('risk', 0)
                    }

        except Exception as e:
            logger.debug(f"Failed to check proxy status for {ip_address}: {e}")

        return {
            'is_proxy': False,
            'checked': False
        }

    def get_asn_info(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get ASN (Autonomous System Number) information

        Args:
            ip_address: IP address

        Returns:
            Dictionary with ASN information
        """
        try:
            # This is extracted from ip-api.com response
            geo_data = self.get_geolocation(ip_address)

            if geo_data and geo_data.get('as'):
                asn_string = geo_data.get('as', '')
                parts = asn_string.split(' ', 1)

                return {
                    'asn': parts[0] if len(parts) > 0 else None,
                    'name': parts[1] if len(parts) > 1 else None,
                    'organization': geo_data.get('org')
                }

        except Exception as e:
            logger.debug(f"Failed to get ASN info for {ip_address}: {e}")

        return None

    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Overall IP reputation check

        Args:
            ip_address: IP address

        Returns:
            Dictionary with reputation score and details
        """
        analysis = self.analyze_ip(ip_address)

        # Calculate reputation score (0-100)
        score = 100

        # Penalties
        if analysis['blacklist_status']['blacklisted']:
            score -= 40

        if analysis['is_proxy'].get('is_proxy'):
            score -= 20

        if analysis['is_proxy'].get('is_vpn'):
            score -= 15

        # Check if residential IP
        if analysis['geolocation']:
            isp = analysis['geolocation'].get('isp', '').lower()
            # If ISP looks like hosting/datacenter, reduce score
            datacenter_keywords = ['amazon', 'google', 'digital ocean', 'ovh', 'hetzner', 'linode']
            if any(keyword in isp for keyword in datacenter_keywords):
                score -= 10

        score = max(0, score)

        return {
            'score': score,
            'reputation': 'good' if score >= 70 else 'moderate' if score >= 40 else 'poor',
            'details': analysis
        }

    def get_detailed_ip_info(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed IP information from ipapi.is
        Включает все флаги: is_bogon, is_datacenter, is_proxy, is_vpn, is_tor,
        is_abuser, is_mobile, is_satellite, is_crawler

        Args:
            ip_address: IP address

        Returns:
            Dictionary with detailed IP flags
        """
        try:
            response = requests.get(
                f'https://api.ipapi.is/?q={ip_address}',
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                detailed_info = {
                    'is_bogon': data.get('is_bogon', False),
                    'is_datacenter': data.get('is_datacenter', False),
                    'is_proxy': data.get('is_proxy', False),
                    'is_vpn': data.get('is_vpn', False),
                    'is_tor': data.get('is_tor', False),
                    'is_abuser': data.get('is_abuser', False),
                    'is_mobile': data.get('is_mobile', False),
                    'is_satellite': data.get('is_satellite', False),
                    'is_crawler': data.get('is_crawler', False),
                    'usage_type': data.get('company', {}).get('type'),
                    'abuse_score': data.get('abuse', {}).get('score', 0),
                    'abuse_reports': data.get('abuse', {}).get('reports', 0)
                }

                logger.info(f"Detailed IP info for {ip_address}: datacenter={detailed_info['is_datacenter']}, abuser={detailed_info['is_abuser']}")
                return detailed_info

        except Exception as e:
            logger.debug(f"Failed to get detailed IP info for {ip_address}: {e}")

        return None

import requests
import hashlib
import time
from typing import Dict, Any, List, Optional
from src.utils.logger import logger
from config.config import config


class VirusTotalAnalyzer:
    """Analyze files and URLs using VirusTotal API"""

    def __init__(self):
        self.api_key = config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key
        } if self.api_key else None

    def analyze_file(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Analyze file through VirusTotal

        Args:
            file_path: Path to file
            filename: Original filename

        Returns:
            Dictionary with scan results
        """
        if not self.api_key:
            return {
                'filename': filename,
                'scanned': False,
                'error': 'VirusTotal API key not configured'
            }

        try:
            # Calculate file hash (SHA256)
            with open(file_path, 'rb') as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()

            logger.info(f"Checking file hash on VirusTotal: {file_hash}")

            # First, check if file already exists in VT database
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                # File already scanned
                data = response.json()
                return self._parse_file_report(data, filename)
            elif response.status_code == 404:
                # File not found, upload for scanning
                logger.info(f"File not found in VT, uploading: {filename}")
                return self._upload_and_scan(file_path, filename, file_hash)
            else:
                logger.warning(f"VirusTotal API returned status {response.status_code}")
                return {
                    'filename': filename,
                    'scanned': False,
                    'error': f'API error: {response.status_code}'
                }

        except Exception as e:
            logger.error(f"Failed to analyze file {filename}: {e}")
            return {
                'filename': filename,
                'scanned': False,
                'error': str(e)
            }

    def _upload_and_scan(self, file_path: str, filename: str, file_hash: str) -> Dict[str, Any]:
        """Upload file to VirusTotal for scanning"""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (filename, f)}
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=self.headers,
                    files=files,
                    timeout=60
                )

            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']

                logger.info(f"File uploaded, waiting for analysis: {analysis_id}")

                # Wait a bit and try to get results (max 3 attempts)
                for attempt in range(3):
                    time.sleep(10)  # Wait 10 seconds between attempts

                    result_response = requests.get(
                        f"{self.base_url}/analyses/{analysis_id}",
                        headers=self.headers,
                        timeout=30
                    )

                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        status = result_data['data']['attributes']['status']

                        if status == 'completed':
                            # Get full file report
                            file_response = requests.get(
                                f"{self.base_url}/files/{file_hash}",
                                headers=self.headers,
                                timeout=30
                            )
                            if file_response.status_code == 200:
                                return self._parse_file_report(file_response.json(), filename)

                logger.warning(f"Analysis timeout for {filename}")
                return {
                    'filename': filename,
                    'scanned': True,
                    'status': 'pending',
                    'message': 'Scan in progress, check later'
                }
            else:
                return {
                    'filename': filename,
                    'scanned': False,
                    'error': f'Upload failed: {response.status_code}'
                }

        except Exception as e:
            logger.error(f"Failed to upload file {filename}: {e}")
            return {
                'filename': filename,
                'scanned': False,
                'error': str(e)
            }

    def _parse_file_report(self, data: Dict[str, Any], filename: str) -> Dict[str, Any]:
        """Parse VirusTotal file report"""
        try:
            attributes = data['data']['attributes']
            stats = attributes['last_analysis_stats']

            return {
                'filename': filename,
                'scanned': True,
                'sha256': attributes.get('sha256'),
                'md5': attributes.get('md5'),
                'file_type': attributes.get('type_description'),
                'size': attributes.get('size'),
                'detections': stats.get('malicious', 0),
                'total_scanners': sum(stats.values()),
                'stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0)
                },
                'is_malicious': stats.get('malicious', 0) > 0,
                'scan_date': attributes.get('last_analysis_date')
            }

        except Exception as e:
            logger.error(f"Failed to parse VT report: {e}")
            return {
                'filename': filename,
                'scanned': False,
                'error': f'Parse error: {e}'
            }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL through VirusTotal

        Args:
            url: URL to check

        Returns:
            Dictionary with scan results
        """
        if not self.api_key:
            return {
                'url': url,
                'scanned': False,
                'error': 'VirusTotal API key not configured'
            }

        try:
            # Calculate URL identifier
            url_id = self._get_url_id(url)

            logger.info(f"Checking URL on VirusTotal: {url}")

            # Check if URL already scanned
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                # URL already scanned
                data = response.json()
                return self._parse_url_report(data, url)
            elif response.status_code == 404:
                # URL not found, submit for scanning
                logger.info(f"URL not found in VT, submitting: {url}")
                return self._submit_url(url)
            else:
                logger.warning(f"VirusTotal API returned status {response.status_code}")
                return {
                    'url': url,
                    'scanned': False,
                    'error': f'API error: {response.status_code}'
                }

        except Exception as e:
            logger.error(f"Failed to analyze URL {url}: {e}")
            return {
                'url': url,
                'scanned': False,
                'error': str(e)
            }

    def _submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL to VirusTotal for scanning"""
        try:
            response = requests.post(
                f"{self.base_url}/urls",
                headers=self.headers,
                data={'url': url},
                timeout=30
            )

            if response.status_code == 200:
                logger.info(f"URL submitted for scanning: {url}")
                return {
                    'url': url,
                    'scanned': True,
                    'status': 'pending',
                    'message': 'URL submitted for scanning, check later'
                }
            else:
                return {
                    'url': url,
                    'scanned': False,
                    'error': f'Submit failed: {response.status_code}'
                }

        except Exception as e:
            logger.error(f"Failed to submit URL {url}: {e}")
            return {
                'url': url,
                'scanned': False,
                'error': str(e)
            }

    def _parse_url_report(self, data: Dict[str, Any], url: str) -> Dict[str, Any]:
        """Parse VirusTotal URL report"""
        try:
            attributes = data['data']['attributes']
            stats = attributes['last_analysis_stats']

            return {
                'url': url,
                'scanned': True,
                'detections': stats.get('malicious', 0),
                'total_scanners': sum(stats.values()),
                'stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0)
                },
                'is_malicious': stats.get('malicious', 0) > 0,
                'scan_date': attributes.get('last_analysis_date'),
                'categories': attributes.get('categories', {}),
                'title': attributes.get('title')
            }

        except Exception as e:
            logger.error(f"Failed to parse VT URL report: {e}")
            return {
                'url': url,
                'scanned': False,
                'error': f'Parse error: {e}'
            }

    def _get_url_id(self, url: str) -> str:
        """Get VirusTotal URL identifier (base64 without padding)"""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return url_id

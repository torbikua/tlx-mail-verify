"""Content analyzer for phishing/scam detection in email body"""

import re
import unicodedata
from typing import Dict, Any, List
from html.parser import HTMLParser
from src.utils.logger import logger


class _LinkExtractor(HTMLParser):
    """Extract <a> tags with href and display text"""

    def __init__(self):
        super().__init__()
        self.links = []
        self._current_href = None
        self._current_text = ''

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for name, value in attrs:
                if name == 'href':
                    self._current_href = value
                    self._current_text = ''

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text += data

    def handle_endtag(self, tag):
        if tag == 'a' and self._current_href is not None:
            self.links.append({
                'href': self._current_href,
                'text': self._current_text.strip()
            })
            self._current_href = None
            self._current_text = ''


class ContentAnalyzer:
    """Analyze email content for phishing/scam indicators"""

    # Urgency patterns (EN + RU)
    URGENCY_PATTERNS = [
        # English
        r'act\s+now', r'immediate(?:ly|\s+action)', r'urgent(?:ly)?',
        r'expires?\s+(?:today|soon|in\s+\d+)', r'last\s+chance',
        r'final\s+(?:warning|notice)', r'account\s+will\s+be\s+(?:closed|suspended|terminated|deleted)',
        r'within\s+\d+\s+(?:hours?|days?|minutes?)', r'limited\s+time',
        r'don\'?t\s+delay', r'hurry', r'asap',
        r'respond\s+immediately', r'time\s+is\s+running\s+out',
        r'act\s+before', r'deadline',
        # Russian
        r'срочно', r'немедленно', r'ваш\s+аккаунт\s+(?:будет|заблокирован)',
        r'в\s+течение\s+\d+\s+(?:часов|дней|минут)',
        r'последнее\s+предупреждение', r'действуйте\s+сейчас',
        r'не\s+откладывайте', r'ограниченное\s+время',
        r'истекает\s+(?:сегодня|завтра|скоро)', r'до\s+блокировки',
    ]

    # Credential request patterns
    CREDENTIAL_PATTERNS = [
        # English
        r'(?:enter|verify|confirm|update|validate)\s+(?:your\s+)?(?:password|credentials|login|pin|ssn)',
        r'credit\s+card\s+(?:number|details|information)',
        r'(?:bank|account)\s+(?:number|details|information|credentials)',
        r'social\s+security(?:\s+number)?',
        r'one[-\s]?time\s+(?:password|code|otp)',
        r'verification\s+code', r'security\s+code',
        r'(?:sign|log)\s*in\s+(?:to\s+)?(?:verify|confirm|secure)',
        r'click\s+(?:here|below)\s+to\s+(?:verify|confirm|update|secure)',
        # Russian
        r'(?:введите|подтвердите|обновите|укажите)\s+(?:ваш\s+)?(?:пароль|логин|данные|пин)',
        r'(?:номер|данные)\s+(?:кредитной\s+)?карты',
        r'(?:код|номер)\s+(?:подтверждения|верификации|безопасности)',
        r'перейдите\s+по\s+ссылке\s+для\s+(?:подтверждения|верификации)',
    ]

    # Threat/fear language patterns
    THREAT_PATTERNS = [
        # English
        r'(?:your\s+)?account\s+(?:has\s+been|was|is)\s+(?:compromised|hacked|breached|suspended|locked)',
        r'unauthorized\s+(?:access|transaction|activity|login)',
        r'(?:legal|law\s+enforcement)\s+action',
        r'failure\s+to\s+(?:comply|respond|verify)\s+(?:will|may)\s+result',
        r'will\s+be\s+(?:permanently\s+)?(?:deleted|suspended|terminated|blocked)',
        r'suspicious\s+(?:activity|login|transaction)',
        r'your\s+(?:data|information|account)\s+(?:is|may\s+be)\s+at\s+risk',
        # Russian
        r'несанкционированн(?:ый|ая|ое)\s+(?:доступ|активность|вход)',
        r'подозрительная\s+(?:активность|транзакция|попытка)',
        r'(?:аккаунт|учётная\s+запись)\s+(?:был[аи]?\s+)?(?:взломан|заблокирован|скомпрометирован)',
        r'судебн(?:ое|ые)\s+(?:разбирательств|иск|действи)',
        r'(?:ваши\s+)?данные\s+(?:были\s+)?(?:украдены|скомпрометированы|в\s+опасности)',
        r'штраф|взыскание|блокировка\s+средств',
    ]

    # Suspicious URL patterns
    SUSPICIOUS_URL_PATTERNS = {
        'ip_based': re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        'shortener': re.compile(
            r'https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|'
            r'cutt\.ly|rb\.gy|shorturl\.at|tiny\.cc|v\.gd|bc\.vc|s\.id|clck\.ru|'
            r'qps\.ru|vk\.cc|u\.to)/\S+'
        ),
        'data_uri': re.compile(r'data:text/html'),
        'encoded_domain': re.compile(r'https?://[^/\s]*%[0-9a-fA-F]{2}'),
        'suspicious_tld': re.compile(
            r'https?://[^/\s]+\.(?:xyz|top|club|work|click|link|gq|ml|cf|tk|ga|buzz|icu|cam)\b'
        ),
    }

    # Cyrillic to Latin confusable characters
    CONFUSABLES = {
        '\u0430': 'a',  # а → a
        '\u0435': 'e',  # е → e
        '\u043e': 'o',  # о → o
        '\u0440': 'p',  # р → p
        '\u0441': 'c',  # с → c
        '\u0443': 'y',  # у → y
        '\u0445': 'x',  # х → x
        '\u043d': 'h',  # н → h (visual)
        '\u0456': 'i',  # і → i (Ukrainian)
        '\u0458': 'j',  # ј → j (Serbian)
        '\u043a': 'k',  # к → k (visual)
        '\u0442': 't',  # т → t (visual)
    }

    def __init__(self):
        self._compiled_urgency = [re.compile(p, re.IGNORECASE) for p in self.URGENCY_PATTERNS]
        self._compiled_credentials = [re.compile(p, re.IGNORECASE) for p in self.CREDENTIAL_PATTERNS]
        self._compiled_threats = [re.compile(p, re.IGNORECASE) for p in self.THREAT_PATTERNS]

    def analyze_content(self, body_text: str, body_html: str, urls: List[str],
                        subject: str, sender_domain: str = '') -> Dict[str, Any]:
        """
        Main entry point: analyze email content for phishing indicators

        Args:
            body_text: Plain text body of the email
            body_html: HTML body of the email
            urls: List of URLs extracted from the email
            subject: Email subject line
            sender_domain: Sender's domain for lookalike comparison

        Returns:
            Dict with content_risk_score (0-100) and detailed breakdown
        """
        try:
            # Combine subject + body for text analysis
            full_text = f"{subject}\n{body_text}" if body_text else subject or ''

            urgency = self._detect_urgency(full_text)
            credentials = self._detect_credential_requests(full_text)
            threats = self._detect_threats(full_text)
            suspicious_urls = self._analyze_urls(urls, body_html, sender_domain)
            homograph = self._detect_homograph(sender_domain) if sender_domain else {'detected': False}

            # Calculate overall content risk score
            risk_score = self._calculate_content_risk(
                urgency, credentials, threats, suspicious_urls, homograph
            )

            result = {
                'content_risk_score': risk_score,
                'urgency_indicators': urgency,
                'credential_requests': credentials,
                'threat_language': threats,
                'suspicious_urls': suspicious_urls,
                'homograph_attack': homograph,
                'summary': self._build_summary(risk_score, urgency, credentials, threats, suspicious_urls)
            }

            logger.info(f"Content analysis: risk_score={risk_score}, "
                        f"urgency={urgency['count']}, credentials={credentials['detected']}, "
                        f"threats={threats['detected']}, suspicious_urls={suspicious_urls['total']}")

            return result

        except Exception as e:
            logger.error(f"Content analysis error: {e}")
            return {
                'content_risk_score': 0,
                'urgency_indicators': {'count': 0, 'patterns': []},
                'credential_requests': {'detected': False, 'patterns': []},
                'threat_language': {'detected': False, 'patterns': []},
                'suspicious_urls': {'total': 0, 'ip_based': [], 'shortened': [],
                                    'lookalike': [], 'mismatched_href': [], 'suspicious_tld': []},
                'homograph_attack': {'detected': False},
                'summary': 'Ошибка анализа содержимого'
            }

    def _detect_urgency(self, text: str) -> Dict[str, Any]:
        """Detect urgency/pressure patterns in text"""
        if not text:
            return {'count': 0, 'patterns': []}

        found = []
        for pattern in self._compiled_urgency:
            matches = pattern.findall(text)
            for match in matches:
                matched_text = match if isinstance(match, str) else match[0]
                if matched_text and matched_text not in found:
                    found.append(matched_text.strip().lower())

        return {'count': len(found), 'patterns': found[:10]}

    def _detect_credential_requests(self, text: str) -> Dict[str, Any]:
        """Detect credential/data solicitation patterns"""
        if not text:
            return {'detected': False, 'patterns': []}

        found = []
        for pattern in self._compiled_credentials:
            matches = pattern.findall(text)
            for match in matches:
                matched_text = match if isinstance(match, str) else match[0]
                if matched_text and matched_text not in found:
                    found.append(matched_text.strip().lower())

        return {'detected': len(found) > 0, 'patterns': found[:10]}

    def _detect_threats(self, text: str) -> Dict[str, Any]:
        """Detect threat/fear language"""
        if not text:
            return {'detected': False, 'patterns': []}

        found = []
        for pattern in self._compiled_threats:
            matches = pattern.findall(text)
            for match in matches:
                matched_text = match if isinstance(match, str) else match[0]
                if matched_text and matched_text not in found:
                    found.append(matched_text.strip().lower())

        return {'detected': len(found) > 0, 'patterns': found[:10]}

    def _analyze_urls(self, urls: List[str], body_html: str, sender_domain: str) -> Dict[str, Any]:
        """Analyze URLs for suspicious patterns"""
        result = {
            'ip_based': [],
            'shortened': [],
            'lookalike': [],
            'mismatched_href': [],
            'suspicious_tld': [],
            'total': 0,
        }

        if not urls and not body_html:
            return result

        # Check URL patterns
        for url in (urls or []):
            if self.SUSPICIOUS_URL_PATTERNS['ip_based'].search(url):
                result['ip_based'].append(url[:120])

            if self.SUSPICIOUS_URL_PATTERNS['shortener'].search(url):
                result['shortened'].append(url[:120])

            if self.SUSPICIOUS_URL_PATTERNS['suspicious_tld'].search(url):
                result['suspicious_tld'].append(url[:120])

            if self.SUSPICIOUS_URL_PATTERNS['data_uri'].search(url):
                result['ip_based'].append(url[:120])  # data URIs are high risk too

            # Lookalike domain check
            if sender_domain:
                url_domain = self._extract_domain_from_url(url)
                if url_domain and url_domain != sender_domain:
                    distance = self._levenshtein_distance(url_domain.split('.')[0],
                                                          sender_domain.split('.')[0])
                    if 0 < distance <= 2:
                        result['lookalike'].append({
                            'url': url[:120],
                            'domain': url_domain,
                            'similar_to': sender_domain,
                            'distance': distance
                        })

        # Check mismatched href vs display text in HTML
        if body_html:
            try:
                extractor = _LinkExtractor()
                extractor.feed(body_html[:50000])  # limit HTML parsing
                for link in extractor.links:
                    href_domain = self._extract_domain_from_url(link['href'])
                    display_domain = self._extract_domain_from_url(link['text'])
                    if href_domain and display_domain and href_domain != display_domain:
                        result['mismatched_href'].append({
                            'display': display_domain,
                            'actual': href_domain,
                            'href': link['href'][:120]
                        })
            except Exception as e:
                logger.debug(f"HTML link extraction error: {e}")

        result['total'] = (len(result['ip_based']) + len(result['shortened']) +
                          len(result['lookalike']) + len(result['mismatched_href']) +
                          len(result['suspicious_tld']))

        return result

    def _detect_homograph(self, domain: str) -> Dict[str, Any]:
        """Check for IDN homograph attacks"""
        if not domain:
            return {'detected': False}

        try:
            domain.encode('ascii')
            has_non_ascii = False
        except UnicodeEncodeError:
            has_non_ascii = True

        is_punycode = 'xn--' in domain.lower()

        confusable_chars = []
        for char in domain.split('.')[0]:
            if char in self.CONFUSABLES:
                confusable_chars.append({
                    'char': char,
                    'looks_like': self.CONFUSABLES[char],
                    'name': unicodedata.name(char, 'UNKNOWN')
                })

        detected = has_non_ascii or is_punycode or len(confusable_chars) > 0

        return {
            'detected': detected,
            'has_non_ascii': has_non_ascii,
            'is_punycode': is_punycode,
            'confusable_chars': confusable_chars[:5],
        }

    def _calculate_content_risk(self, urgency: Dict, credentials: Dict,
                                threats: Dict, urls: Dict, homograph: Dict) -> int:
        """Calculate 0-100 content danger score"""
        score = 0

        # Urgency (max 25 points)
        urgency_count = urgency.get('count', 0)
        if urgency_count >= 3:
            score += 25
        elif urgency_count == 2:
            score += 18
        elif urgency_count == 1:
            score += 10

        # Credential requests (max 30 points) - strongest indicator
        if credentials.get('detected'):
            cred_count = len(credentials.get('patterns', []))
            score += min(30, 15 + cred_count * 5)

        # Threat language (max 20 points)
        if threats.get('detected'):
            threat_count = len(threats.get('patterns', []))
            score += min(20, 10 + threat_count * 5)

        # Suspicious URLs (max 25 points)
        if urls.get('ip_based'):
            score += 15
        if urls.get('shortened'):
            score += 5
        if urls.get('mismatched_href'):
            score += min(15, len(urls['mismatched_href']) * 8)
        if urls.get('lookalike'):
            score += 10
        if urls.get('suspicious_tld'):
            score += min(5, len(urls['suspicious_tld']) * 2)

        # Homograph attack (bonus 15 points)
        if homograph.get('detected'):
            score += 15

        return min(100, score)

    def _build_summary(self, risk_score: int, urgency: Dict, credentials: Dict,
                       threats: Dict, urls: Dict) -> str:
        """Build human-readable summary"""
        parts = []

        if risk_score >= 60:
            parts.append('Высокий риск')
        elif risk_score >= 30:
            parts.append('Средний риск')
        else:
            parts.append('Низкий риск')

        if urgency.get('count', 0) > 0:
            parts.append(f"{urgency['count']} индикаторов срочности")
        if credentials.get('detected'):
            parts.append('запрос учётных данных')
        if threats.get('detected'):
            parts.append('язык угроз')
        if urls.get('total', 0) > 0:
            parts.append(f"{urls['total']} подозрительных URL")

        return ': '.join(parts[:1]) + ' — ' + ', '.join(parts[1:]) if len(parts) > 1 else parts[0]

    @staticmethod
    def _extract_domain_from_url(url: str) -> str:
        """Extract domain from URL string"""
        if not url:
            return ''
        # Remove protocol
        url = re.sub(r'^https?://', '', url)
        # Remove path
        url = url.split('/')[0]
        # Remove port
        url = url.split(':')[0]
        # Remove www.
        url = re.sub(r'^www\.', '', url)
        return url.lower().strip() if url else ''

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return ContentAnalyzer._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

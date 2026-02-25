import anthropic
from typing import Dict, Any, Optional
from config.config import config
from src.utils.logger import logger


class ClaudeService:
    """Service for interacting with Claude API"""

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        self.model = config.CLAUDE_MODEL
        self.max_tokens = config.CLAUDE_MAX_TOKENS

    def analyze_email_security(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze all collected data and provide final verdict using Claude

        Args:
            analysis_data: Dictionary with all analysis results

        Returns:
            Dictionary with Claude's analysis and verdict
        """
        try:
            # Prepare analysis summary for Claude
            prompt = self._build_analysis_prompt(analysis_data)

            # Call Claude API
            message = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            # Extract response
            analysis_text = message.content[0].text

            # Parse response for structured data
            verdict = self._extract_verdict(analysis_text)

            result = {
                'full_analysis': analysis_text,
                'verdict': verdict['verdict'],
                'risk_level': verdict['risk_level'],
                'confidence': verdict['confidence'],
                'key_findings': verdict['key_findings'],
                'recommendations': verdict['recommendations']
            }

            logger.info(f"Claude analysis completed: verdict={verdict['verdict']}, risk={verdict['risk_level']}")
            return result

        except Exception as e:
            logger.error(f"Claude API error: {e}")
            return {
                'error': str(e),
                'full_analysis': None,
                'verdict': 'Невозможно определить',
                'risk_level': 'yellow',
                'confidence': 0
            }

    def _build_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build comprehensive prompt for Claude"""

        prompt = f"""Ты эксперт по кибербезопасности и анализу электронной почты. Проанализируй следующие данные о письме и определи, является ли оно легитимным или подозрительным/фишинговым.

**ДАННЫЕ ПИСЬМА:**

**1. Основная информация:**
- От: {data.get('from_address', 'N/A')} ({data.get('from_name', 'N/A')})
- Тема: {data.get('subject', 'N/A')}
- Дата: {data.get('date', 'N/A')}

**2. Проверка подлинности (DKIM/SPF/DMARC):**
- DKIM валиден: {data.get('dkim', {}).get('valid', False)}
- SPF валиден: {data.get('spf', {}).get('valid', False)}
- DMARC найден: {data.get('dmarc', {}).get('valid', False)}
- Политика DMARC: {data.get('dmarc', {}).get('policy', 'N/A')}

**3. Анализ домена:**
- Домен: {data.get('domain', 'N/A')}
- Возраст домена: {data.get('domain_age_days', 'N/A')} дней
- Регистратор: {data.get('registrar', 'N/A')}
- WHOIS: {self._format_whois(data.get('whois', {}))}
- MX записи найдены: {bool(data.get('mx_records', []))}

**4. Анализ IP отправителя:**
- IP: {data.get('sender_ip', 'N/A')}
- Геолокация: {self._format_geolocation(data.get('ip_location', {}))}
- В черных списках: {data.get('ip_blacklisted', False)}
- Количество blacklist: {data.get('blacklist_count', 0)}
- Является прокси/VPN: {data.get('is_proxy', False)}

**5. Анализ сайта:**
- Сайт существует: {data.get('website_exists', False)}
- HTTPS доступен: {data.get('https_accessible', False)}
- SSL валиден: {data.get('ssl_valid', False)}
- Срок действия SSL: {data.get('ssl_days_left', 'N/A')} дней
- Обнаруженные технологии: {data.get('technologies', 'N/A')}

**6. OSINT данные:**
- Email в утечках: {data.get('email_in_breaches', False)}
- Социальные профили найдены: {data.get('social_profiles_found', False)}
- Одноразовый email: {data.get('is_disposable', False)}

**ЗАДАЧА:**

Проанализируй все данные и предоставь:

1. **ВЕРДИКТ** (одно из):
   - "ЛЕГИТИМНОЕ" - письмо безопасное и от настоящего отправителя
   - "ПОДОЗРИТЕЛЬНОЕ" - есть тревожные признаки, требуется осторожность
   - "ФИШИНГ" - высокая вероятность фишинговой атаки

2. **УРОВЕНЬ РИСКА** (один из):
   - "green" (🟢) - безопасно
   - "yellow" (🟡) - требует внимания
   - "red" (🔴) - опасно

3. **УВЕРЕННОСТЬ** (0-100%): Насколько ты уверен в своем вердикте

4. **КЛЮЧЕВЫЕ НАХОДКИ** (список из 3-5 пунктов): Самые важные факты, на которых основан вердикт

5. **РЕКОМЕНДАЦИИ** (список из 2-4 пунктов): Что делать получателю

Отформатируй ответ так:

---ВЕРДИКТ---
[ЛЕГИТИМНОЕ/ПОДОЗРИТЕЛЬНОЕ/ФИШИНГ]

---РИСК---
[green/yellow/red]

---УВЕРЕННОСТЬ---
[0-100]

---НАХОДКИ---
- [Находка 1]
- [Находка 2]
- [Находка 3]

---РЕКОМЕНДАЦИИ---
- [Рекомендация 1]
- [Рекомендация 2]

---АНАЛИЗ---
[Подробный анализ всех аспектов письма]
"""

        return prompt

    def _format_whois(self, whois: Dict[str, Any]) -> str:
        """Format WHOIS data for prompt"""
        if not whois:
            return "N/A"

        parts = []
        if whois.get('org'):
            parts.append(f"Org: {whois['org']}")
        if whois.get('country'):
            parts.append(f"Country: {whois['country']}")
        if whois.get('creation_date'):
            parts.append(f"Created: {whois['creation_date']}")

        return ", ".join(parts) if parts else "N/A"

    def _format_geolocation(self, geo: Dict[str, Any]) -> str:
        """Format geolocation data for prompt"""
        if not geo:
            return "N/A"

        parts = []
        if geo.get('country'):
            parts.append(geo['country'])
        if geo.get('city'):
            parts.append(geo['city'])
        if geo.get('isp'):
            parts.append(f"ISP: {geo['isp']}")

        return ", ".join(parts) if parts else "N/A"

    def _extract_verdict(self, analysis_text: str) -> Dict[str, Any]:
        """Extract structured data from Claude's response"""
        import re

        result = {
            'verdict': 'Невозможно определить',
            'risk_level': 'yellow',
            'confidence': 50,
            'key_findings': [],
            'recommendations': []
        }

        try:
            # Extract verdict
            verdict_match = re.search(r'---ВЕРДИКТ---\s*\n\s*([А-ЯЁ]+)', analysis_text)
            if verdict_match:
                result['verdict'] = verdict_match.group(1)

            # Extract risk level
            risk_match = re.search(r'---РИСК---\s*\n\s*(\w+)', analysis_text)
            if risk_match:
                result['risk_level'] = risk_match.group(1).lower()

            # Extract confidence
            confidence_match = re.search(r'---УВЕРЕННОСТЬ---\s*\n\s*(\d+)', analysis_text)
            if confidence_match:
                result['confidence'] = int(confidence_match.group(1))

            # Extract findings
            findings_match = re.search(r'---НАХОДКИ---\s*\n((?:- .+\n?)+)', analysis_text)
            if findings_match:
                findings_text = findings_match.group(1)
                result['key_findings'] = [
                    line.strip('- ').strip()
                    for line in findings_text.split('\n')
                    if line.strip().startswith('-')
                ]

            # Extract recommendations
            recommendations_match = re.search(r'---РЕКОМЕНДАЦИИ---\s*\n((?:- .+\n?)+)', analysis_text)
            if recommendations_match:
                rec_text = recommendations_match.group(1)
                result['recommendations'] = [
                    line.strip('- ').strip()
                    for line in rec_text.split('\n')
                    if line.strip().startswith('-')
                ]

        except Exception as e:
            logger.error(f"Failed to parse Claude response: {e}")

        return result

    def generate_summary(self, analysis_data: Dict[str, Any], language: str = 'ru') -> str:
        """
        Generate a concise HTML summary for email response

        Args:
            analysis_data: Analysis results with Claude verdict
            language: Language for summary (ru or en)

        Returns:
            Formatted HTML summary
        """
        try:
            risk_level = analysis_data.get('risk_level', 'yellow')
            verdict = analysis_data.get('verdict', 'Невозможно определить')

            # Risk emoji
            risk_emoji = {
                'green': '🟢',
                'yellow': '🟡',
                'red': '🔴'
            }.get(risk_level, '🟡')

            # Risk color for styling
            risk_color = {
                'green': '#28a745',
                'yellow': '#ffc107',
                'red': '#dc3545'
            }.get(risk_level, '#ffc107')

            if language == 'ru':
                findings_html = ""
                for finding in analysis_data.get('key_findings', [])[:5]:
                    findings_html += f"<li>{finding}</li>\n"

                recommendations_html = ""
                for rec in analysis_data.get('recommendations', [])[:3]:
                    recommendations_html += f"<li>{rec}</li>\n"

                summary = f"""
<div style="font-family: Arial, sans-serif; max-width: 750px; margin: 0 auto;">
    <h2 style="color: {risk_color};">{risk_emoji} РЕЗУЛЬТАТ ПРОВЕРКИ ПИСЬМА</h2>

    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <p><b>Вердикт:</b> <span style="color: {risk_color}; font-weight: bold;">{verdict}</span></p>
        <p><b>Уровень риска:</b> {risk_emoji} <span style="color: {risk_color}; font-weight: bold;">{risk_level.upper()}</span></p>
        <p><b>Оценка достоверности:</b> {analysis_data.get('overall_score', 0)}/100</p>
    </div>

    <h3>Ключевые находки:</h3>
    <ul style="line-height: 1.6;">
        {findings_html}
    </ul>

    <h3>Рекомендации:</h3>
    <ul style="line-height: 1.6;">
        {recommendations_html}
    </ul>

    <p style="margin-top: 20px; padding: 10px; background-color: #e7f3ff; border-left: 4px solid #2196F3;">
        📎 <b>Подробный PDF отчет прикреплен к письму.</b>
    </p>
</div>
"""

            else:
                findings_html = ""
                for finding in analysis_data.get('key_findings', [])[:5]:
                    findings_html += f"<li>{finding}</li>\n"

                recommendations_html = ""
                for rec in analysis_data.get('recommendations', [])[:3]:
                    recommendations_html += f"<li>{rec}</li>\n"

                summary = f"""
<div style="font-family: Arial, sans-serif; max-width: 750px; margin: 0 auto;">
    <h2 style="color: {risk_color};">{risk_emoji} EMAIL VERIFICATION RESULT</h2>

    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <p><b>Verdict:</b> <span style="color: {risk_color}; font-weight: bold;">{verdict}</span></p>
        <p><b>Risk Level:</b> {risk_emoji} <span style="color: {risk_color}; font-weight: bold;">{risk_level.upper()}</span></p>
        <p><b>Confidence Score:</b> {analysis_data.get('overall_score', 0)}/100</p>
    </div>

    <h3>Key Findings:</h3>
    <ul style="line-height: 1.6;">
        {findings_html}
    </ul>

    <h3>Recommendations:</h3>
    <ul style="line-height: 1.6;">
        {recommendations_html}
    </ul>

    <p style="margin-top: 20px; padding: 10px; background-color: #e7f3ff; border-left: 4px solid #2196F3;">
        📎 <b>Detailed PDF report attached.</b>
    </p>
</div>
"""

            return summary

        except Exception as e:
            logger.error(f"Failed to generate summary: {e}")
            return f"<div style='font-family: Arial, sans-serif;'><h3>{risk_emoji} Анализ завершен</h3><p>Подробный отчет во вложении.</p></div>"

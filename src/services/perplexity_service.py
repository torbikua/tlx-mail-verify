import openai
from typing import Dict, Any
from config.config import config
from src.utils.logger import logger


class PerplexityService:
    """Service for interacting with Perplexity API"""

    def __init__(self):
        # Perplexity uses OpenAI-compatible API
        self.client = openai.OpenAI(
            api_key=config.PERPLEXITY_API_KEY,
            base_url="https://api.perplexity.ai"
        )
        self.model = config.PERPLEXITY_MODEL
        self.max_tokens = config.PERPLEXITY_MAX_TOKENS

    def analyze_email_security(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze all collected data and provide final verdict using Perplexity

        Args:
            analysis_data: Dictionary with all analysis results

        Returns:
            Dictionary with Perplexity's analysis and verdict
        """
        try:
            # Use custom prompt from .env or build default
            if config.PERPLEXITY_ANALYSIS_PROMPT:
                prompt = self._build_custom_prompt(analysis_data)
            else:
                prompt = self._build_analysis_prompt(analysis_data)

            # Call Perplexity API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "Ты эксперт по кибербезопасности и анализу email на предмет фишинга и скама. Отвечай на русском языке."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=self.max_tokens,
                temperature=0.2,
            )

            # Extract response
            analysis_text = response.choices[0].message.content

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

            logger.info(f"Perplexity analysis completed: verdict={verdict['verdict']}, risk={verdict['risk_level']}")
            return result

        except Exception as e:
            logger.error(f"Perplexity API error: {e}")
            return {
                'error': str(e),
                'full_analysis': None,
                'verdict': 'Невозможно определить',
                'risk_level': 'yellow',
                'confidence': 0
            }

    def _build_custom_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt using custom template from .env"""

        # Replace template variables with actual data
        prompt = config.PERPLEXITY_ANALYSIS_PROMPT

        # Basic replacements
        replacements = {
            '{from_address}': str(data.get('from_address', 'N/A')),
            '{from_name}': str(data.get('from_name', 'N/A')),
            '{subject}': str(data.get('subject', 'N/A')),
            '{date}': str(data.get('date', 'N/A')),
            '{domain}': str(data.get('domain', 'N/A')),
            '{domain_age_days}': str(data.get('domain_age_days', 'N/A')),
            '{sender_ip}': str(data.get('sender_ip', 'N/A')),
            '{dkim_valid}': str(data.get('dkim', {}).get('valid', False)),
            '{spf_valid}': str(data.get('spf', {}).get('valid', False)),
            '{dmarc_valid}': str(data.get('dmarc', {}).get('valid', False)),
            '{ip_blacklisted}': str(data.get('ip_blacklisted', False)),
            '{is_proxy}': str(data.get('is_proxy', False)),
            '{geolocation}': self._format_geolocation(data.get('ip_location', {})),
        }

        for key, value in replacements.items():
            prompt = prompt.replace(key, value)

        return prompt

    def _build_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build comprehensive default prompt for Perplexity"""

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

**7. Текст письма (фрагмент):**
```
{(data.get('body_text', '') or '')[:2000] or 'Текст письма не извлечён'}
```

**8. Автоматический анализ содержимого:**
- Оценка риска содержимого: {data.get('content_risk_score', 'N/A')}/100
- Индикаторы срочности: {(data.get('content_analysis') or {{}}).get('urgency_indicators', {{}}).get('count', 0)} обнаружено
- Запросы учётных данных: {'ОБНАРУЖЕНЫ' if (data.get('content_analysis') or {{}}).get('credential_requests', {{}}).get('detected') else 'Нет'}
- Язык угроз: {'ОБНАРУЖЕН' if (data.get('content_analysis') or {{}}).get('threat_language', {{}}).get('detected') else 'Нет'}
- Подозрительные ссылки: {(data.get('content_analysis') or {{}}).get('suspicious_urls', {{}}).get('total', 0)}

{self._format_ip_details(data.get('ip_detailed_info'))}

{self._format_vt_results(data)}

**ЗАДАЧА:**

ВАЖНО: Учитывай результаты автоматического анализа содержимого (раздел 8). Если обнаружены индикаторы фишинга (запросы учётных данных, язык срочности/угроз, подозрительные ссылки), это СУЩЕСТВЕННЫЕ факторы для вердикта. Не игнорируй технические данные в пользу "общего впечатления".

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

    def _format_ip_details(self, detailed_ip: Dict) -> str:
        """Format detailed IP infrastructure flags for prompt"""
        if not detailed_ip:
            return ""
        parts = ["**Детали IP инфраструктуры:**"]
        flags = [
            ('is_datacenter', 'Датацентр'),
            ('is_vpn', 'VPN'),
            ('is_tor', 'Tor'),
            ('is_proxy', 'Прокси'),
            ('is_abuser', 'Абьюзер'),
            ('is_mobile', 'Мобильная сеть'),
            ('is_crawler', 'Краулер'),
        ]
        for key, label in flags:
            val = detailed_ip.get(key)
            if val is not None:
                parts.append(f"- {label}: {'Да' if val else 'Нет'}")
        abuse_score = detailed_ip.get('abuse_score')
        if abuse_score is not None:
            parts.append(f"- Оценка злоупотреблений: {abuse_score}")
        return '\n'.join(parts) if len(parts) > 1 else ""

    def _format_vt_results(self, data: Dict) -> str:
        """Format VirusTotal results for prompt"""
        vt_attachments = data.get('virustotal_attachments', [])
        vt_urls = data.get('virustotal_urls', [])
        if not vt_attachments and not vt_urls:
            return "**9. VirusTotal:** Не проверялось"
        parts = ["**9. Результаты VirusTotal:**"]
        for att in vt_attachments:
            if att.get('scanned'):
                parts.append(f"- Файл {att.get('filename', '?')[:60]}: "
                           f"{att.get('detections', 0)}/{att.get('total_scanners', 0)} обнаружений")
        for url_d in vt_urls[:5]:
            if url_d.get('scanned'):
                parts.append(f"- URL {url_d.get('url', '')[:60]}: "
                           f"{url_d.get('detections', 0)}/{url_d.get('total_scanners', 0)} обнаружений")
        if len(parts) == 1:
            parts.append("- Результатов нет")
        return '\n'.join(parts)

    def _extract_verdict(self, analysis_text: str) -> Dict[str, Any]:
        """Extract structured data from Perplexity's response"""
        import re

        result = {
            'verdict': 'Невозможно определить',
            'risk_level': 'yellow',
            'confidence': 50,
            'key_findings': [],
            'recommendations': []
        }

        try:
            # Extract verdict - more flexible regex
            verdict_match = re.search(r'---ВЕРДИКТ---\s*\n\s*[\["]?([А-ЯЁ\s/]+?)[\]"]?(?:\s*\n|$)', analysis_text, re.IGNORECASE)
            if verdict_match:
                verdict = verdict_match.group(1).strip()
                result['verdict'] = verdict
                logger.debug(f"Extracted verdict: {verdict}")
            else:
                # Fallback: search for keywords in text
                text_lower = analysis_text.lower()
                if 'легитимное' in text_lower or 'безопасно' in text_lower:
                    result['verdict'] = 'ЛЕГИТИМНОЕ'
                    logger.info("Verdict extracted via fallback: ЛЕГИТИМНОЕ")
                elif 'фишинг' in text_lower or 'скам' in text_lower:
                    result['verdict'] = 'ФИШИНГ'
                    logger.info("Verdict extracted via fallback: ФИШИНГ")
                elif 'подозрительн' in text_lower:
                    result['verdict'] = 'ПОДОЗРИТЕЛЬНОЕ'
                    logger.info("Verdict extracted via fallback: ПОДОЗРИТЕЛЬНОЕ")
                else:
                    logger.warning(f"Could not extract verdict from response. First 500 chars: {analysis_text[:500]}")

            # Extract risk level - more flexible
            risk_match = re.search(r'---РИСК---\s*\n\s*[\["]?(\w+)[\]"]?', analysis_text)
            if risk_match:
                result['risk_level'] = risk_match.group(1).lower()
                logger.debug(f"Extracted risk: {result['risk_level']}")
            else:
                # Fallback: derive from verdict
                if result['verdict'] == 'ЛЕГИТИМНОЕ':
                    result['risk_level'] = 'green'
                elif result['verdict'] == 'ФИШИНГ':
                    result['risk_level'] = 'red'
                else:
                    result['risk_level'] = 'yellow'
                logger.info(f"Risk level derived from verdict: {result['risk_level']}")

            # Extract confidence - more flexible
            confidence_match = re.search(r'---УВЕРЕННОСТЬ---\s*\n\s*(\d+)', analysis_text)
            if confidence_match:
                result['confidence'] = int(confidence_match.group(1))
                logger.debug(f"Extracted confidence: {result['confidence']}")
            else:
                # Estimate based on verdict
                if result['verdict'] != 'Невозможно определить':
                    result['confidence'] = 70  # Default confidence if parsed
                logger.info(f"Confidence estimated: {result['confidence']}")

            # Extract findings (support various bullet formats)
            findings_match = re.search(r'---НАХОДКИ---\s*\n(.+?)(?=\n---|\Z)', analysis_text, re.DOTALL)
            if findings_match:
                findings_text = findings_match.group(1)
                findings_list = []
                for line in findings_text.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    # Remove markdown ** first
                    line = line.replace('**', '')
                    # Remove various bullet markers: •, -, *, numbers (1., 2., 3))
                    cleaned = re.sub(r'^[\s•\-\*]+', '', line).strip()  # Remove leading bullets
                    cleaned = re.sub(r'^\d+[\.\)]\s*', '', cleaned).strip()  # Remove leading numbers
                    if cleaned and len(cleaned) > 10:  # Ignore very short lines
                        findings_list.append(cleaned)
                result['key_findings'] = findings_list[:10]  # Limit to 10 findings
                logger.debug(f"Extracted {len(result['key_findings'])} findings")

            # Extract recommendations (support various bullet formats)
            recommendations_match = re.search(r'---РЕКОМЕНДАЦИИ---\s*\n(.+?)(?=\n---|\Z)', analysis_text, re.DOTALL)
            if recommendations_match:
                rec_text = recommendations_match.group(1)
                rec_list = []
                for line in rec_text.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    # Remove markdown ** first
                    line = line.replace('**', '')
                    # Remove various bullet markers: •, -, *, numbers (1., 2., 3))
                    cleaned = re.sub(r'^[\s•\-\*]+', '', line).strip()  # Remove leading bullets
                    cleaned = re.sub(r'^\d+[\.\)]\s*', '', cleaned).strip()  # Remove leading numbers
                    if cleaned and len(cleaned) > 10:  # Ignore very short lines
                        rec_list.append(cleaned)
                result['recommendations'] = rec_list[:10]  # Limit to 10 recommendations
                logger.debug(f"Extracted {len(result['recommendations'])} recommendations")

        except Exception as e:
            logger.error(f"Failed to parse Perplexity response: {e}")

        return result

    def generate_summary(self, analysis_data: Dict[str, Any], language: str = 'ru') -> str:
        """
        Generate a concise HTML summary for email response

        Args:
            analysis_data: Analysis results with Perplexity verdict
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

                # Determine AI provider name
                ai_provider = analysis_data.get('ai_provider', 'AI')
                ai_names = {
                    'perplexity': 'Perplexity AI',
                    'claude': 'Claude AI',
                    'openai': 'OpenAI GPT'
                }
                ai_name = ai_names.get(ai_provider.lower(), 'AI')

                summary = f"""
<div style="font-family: Arial, sans-serif; max-width: 750px; margin: 0 auto;">
    <h2 style="color: {risk_color};">{risk_emoji} РЕЗУЛЬТАТ ПРОВЕРКИ ПИСЬМА</h2>

    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <p><b>Вердикт:</b> <span style="color: {risk_color}; font-weight: bold;">{verdict}</span></p>
        <p><b>Уровень риска:</b> {risk_emoji} <span style="color: {risk_color}; font-weight: bold;">{risk_level.upper()}</span></p>
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
        <b>Подробный PDF отчет прикреплен к письму.</b>
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

                # Determine AI provider name
                ai_provider = analysis_data.get('ai_provider', 'AI')
                ai_names = {
                    'perplexity': 'Perplexity AI',
                    'claude': 'Claude AI',
                    'openai': 'OpenAI GPT'
                }
                ai_name = ai_names.get(ai_provider.lower(), 'AI')

                summary = f"""
<div style="font-family: Arial, sans-serif; max-width: 750px; margin: 0 auto;">
    <h2 style="color: {risk_color};">{risk_emoji} EMAIL VERIFICATION RESULT</h2>

    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <p><b>Verdict:</b> <span style="color: {risk_color}; font-weight: bold;">{verdict}</span></p>
        <p><b>Risk Level:</b> {risk_emoji} <span style="color: {risk_color}; font-weight: bold;">{risk_level.upper()}</span></p>
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
        <b>Detailed PDF report attached.</b>
    </p>
</div>
"""

            return summary

        except Exception as e:
            logger.error(f"Failed to generate summary: {e}")
            return f"<div style='font-family: Arial, sans-serif;'><h3>{risk_emoji} Анализ завершен</h3><p>Подробный отчет во вложении.</p></div>"

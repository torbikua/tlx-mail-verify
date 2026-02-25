from openai import OpenAI
from typing import Dict, Any, Optional
from config.config import config
from src.utils.logger import logger


class OpenAIService:
    """Service for interacting with OpenAI API (GPT-4/GPT-5)"""

    def __init__(self):
        # CRITICAL FIX: Add timeout to prevent hanging indefinitely
        # Timeout is configurable via OPENAI_API_TIMEOUT in .env
        # Default: 300 seconds (5 minutes) - sufficient for deep reasoning models like GPT-5/O1
        self.api_timeout = float(config.OPENAI_API_TIMEOUT)

        self.client = OpenAI(
            api_key=config.OPENAI_API_KEY,
            timeout=self.api_timeout,  # Configurable timeout
            max_retries=2   # Retry failed requests up to 2 times
        )
        self.model = config.OPENAI_MODEL
        self.max_tokens = config.OPENAI_MAX_TOKENS
        self.temperature = config.OPENAI_TEMPERATURE
        self.deep_research = config.OPENAI_DEEP_RESEARCH
        self.research_steps = config.OPENAI_RESEARCH_STEPS

        # Check if using O1 or GPT-5 reasoning models
        self.is_o1_model = 'o1' in self.model.lower() or 'gpt-5' in self.model.lower()

        if self.is_o1_model:
            logger.info(f"Using reasoning model: {self.model} - Deep analysis mode enabled")

        logger.info(f"OpenAI client initialized: timeout={self.api_timeout}s, max_retries=2, model={self.model}")

    def analyze_email_security(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze all collected data and provide final verdict using OpenAI

        Args:
            analysis_data: Dictionary with all analysis results

        Returns:
            Dictionary with OpenAI's analysis and verdict
        """
        try:
            # Check if deep research mode is enabled and multiple passes are requested
            if self.deep_research and self.research_steps > 1:
                logger.info(f"Deep research mode: {self.research_steps} analysis passes")
                return self._deep_research_analysis(analysis_data)
            else:
                return self._single_pass_analysis(analysis_data)

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return {
                'error': str(e),
                'full_analysis': None,
                'verdict': 'Невозможно определить',
                'risk_level': 'yellow',
                'confidence': 0
            }

    def _single_pass_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform single-pass analysis"""
        try:
            # Prepare analysis summary for OpenAI
            prompt = self._build_analysis_prompt(analysis_data)

            # Build messages based on model type
            if self.is_o1_model:
                # O1 models: include system prompt in user message, no temperature
                full_prompt = f"{self._get_system_prompt()}\n\n{prompt}"
                messages = [{"role": "user", "content": full_prompt}]
                api_params = {
                    "model": self.model,
                    "messages": messages,
                    "max_completion_tokens": self.max_tokens  # O1 uses max_completion_tokens
                }
                logger.info("Using O1 reasoning model - extended thinking enabled")
            else:
                # Regular models: separate system and user messages
                messages = [
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ]
                api_params = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": self.temperature,
                    "top_p": 0.95
                }
                # Only add max_tokens for older GPT-4 models that support it
                if 'gpt-4' in self.model.lower() and 'turbo' not in self.model.lower():
                    api_params["max_tokens"] = self.max_tokens

            # Call OpenAI API
            logger.info(f"Calling OpenAI API ({self.model})...")
            response = self.client.chat.completions.create(**api_params)

            # Extract response
            analysis_text = response.choices[0].message.content

            # CRITICAL: Check for empty response
            if not analysis_text or len(analysis_text.strip()) == 0:
                logger.error("OpenAI returned empty response!")
                raise ValueError("API returned empty content")

            # Debug logging
            logger.info(f"Single pass - content length: {len(analysis_text)}")
            logger.info(f"Single pass - preview: {analysis_text[:200]}")

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

            logger.info(f"Analysis completed: verdict={verdict['verdict']}, risk={verdict['risk_level']}")
            return result

        except Exception as e:
            logger.error(f"Single pass analysis failed: {e}")
            # Re-raise to be caught by main error handler
            raise

    def _deep_research_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform multi-step deep research analysis
        Each step refines the previous analysis
        """
        logger.info(f"Starting deep research with {self.research_steps} passes...")

        # Step 1: Initial comprehensive analysis
        initial_result = self._single_pass_analysis(analysis_data)

        if self.research_steps == 1:
            return initial_result

        # Step 2+: Refine analysis with previous findings
        refined_prompt = f"""Ты уже провел первичный анализ письма. Вот твои начальные находки:

**Первичный вердикт:** {initial_result['verdict']}
**Уровень риска:** {initial_result['risk_level']}
**Ключевые находки:**
{chr(10).join(f'- {f}' for f in initial_result['key_findings'])}

**Полный анализ:**
{initial_result['full_analysis']}

---

ТЕПЕРЬ проведи УГЛУБЛЕННУЮ ПОВТОРНУЮ ПРОВЕРКУ:

1. Перепроверь свои выводы - возможно ли что-то упустил?
2. Ищи скрытые индикаторы и тонкие несоответствия
3. Рассмотри альтернативные объяснения данных
4. Проверь логические связи между разными факторами
5. Убедись в правильности итогового вердикта

Предоставь ОКОНЧАТЕЛЬНЫЙ уточненный анализ в том же формате."""

        if self.is_o1_model:
            full_prompt = f"{self._get_system_prompt()}\n\n{self._build_analysis_prompt(analysis_data)}\n\n{refined_prompt}"
            messages = [{"role": "user", "content": full_prompt}]
            api_params = {
                "model": self.model,
                "messages": messages,
                "max_completion_tokens": self.max_tokens
            }
        else:
            messages = [
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": self._build_analysis_prompt(analysis_data)},
                {"role": "assistant", "content": initial_result['full_analysis']},
                {"role": "user", "content": refined_prompt}
            ]
            api_params = {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature * 0.7,  # Lower temp for refinement
                "top_p": 0.95
            }
            # Only add max_tokens for older GPT-4 models that support it
            if 'gpt-4' in self.model.lower() and 'turbo' not in self.model.lower():
                api_params["max_tokens"] = self.max_tokens

        logger.info("Pass 2: Refining analysis with deeper investigation...")
        response = self.client.chat.completions.create(**api_params)
        refined_text = response.choices[0].message.content

        # CRITICAL: Check for empty response
        if not refined_text or len(refined_text.strip()) == 0:
            logger.error("OpenAI returned empty response on pass 2!")
            logger.warning("Falling back to initial analysis results due to empty refinement")
            # Return initial result instead of failing completely
            return {
                'full_analysis': initial_result['full_analysis'] + "\n\n⚠️ Примечание: Вторичный анализ не удался, используется первичный результат.",
                'verdict': initial_result['verdict'],
                'risk_level': initial_result['risk_level'],
                'confidence': max(0, initial_result['confidence'] - 10),  # Reduce confidence slightly
                'key_findings': initial_result['key_findings'],
                'recommendations': initial_result['recommendations'],
                'research_passes': 1,  # Only 1 pass succeeded
                'initial_verdict': initial_result['verdict']
            }

        # Debug logging
        logger.info(f"Pass 2 - content length: {len(refined_text)}")
        logger.info(f"Pass 2 - preview: {refined_text[:500]}")

        # Parse refined response
        refined_verdict = self._extract_verdict(refined_text)

        final_result = {
            'full_analysis': refined_text,
            'verdict': refined_verdict['verdict'],
            'risk_level': refined_verdict['risk_level'],
            'confidence': refined_verdict['confidence'],
            'key_findings': refined_verdict['key_findings'],
            'recommendations': refined_verdict['recommendations'],
            'research_passes': 2,
            'initial_verdict': initial_result['verdict']
        }

        logger.info(f"Deep research completed: {initial_result['verdict']} → {refined_verdict['verdict']}")
        return final_result

    def _get_system_prompt(self) -> str:
        """Get system prompt for AI behavior"""
        # Check if custom prompt is provided in .env
        if config.ANALYSIS_PROMPT_TEMPLATE:
            return config.ANALYSIS_PROMPT_TEMPLATE

        # Default system prompt - глубокое исследование как в примере пользователя
        return """Ты эксперт-аналитик по кибербезопасности, специализирующийся на глубоком OSINT-исследовании email-угроз.

Твоя задача - провести детальное multi-layer исследование письма и создать ИСЧЕРПЫВАЮЩИЙ отчет в структурированном формате.

СТРУКТУРА ТВОЕГО АНАЛИЗА (обязательные разделы):

1. ВОЗРАСТ И ИСТОРИЯ ДОМЕНА
   - Когда зарегистрирован домен (точная дата если возможно)
   - История компании/организации владельца
   - Репутация домена в интернете
   - Есть ли домен в блэклистах Spamhaus, SURBL и др.

2. EMAIL АДРЕС ОТПРАВИТЕЛЯ - OSINT
   - Упоминания email в открытых источниках
   - Связь с реальным человеком/компанией (LinkedIn, профили)
   - Присутствие в базах спама/скама
   - Проверка в Have I Been Pwned и базах утечек

3. ТЕХНИЧЕСКИЕ ПАРАМЕТРЫ (DKIM/SPF/DMARC)
   - Детальный анализ каждой проверки
   - Источник валидации (Gmail Authentication-Results vs self-check)
   - Alignment домена и подписей
   - Настройки DMARC политики

4. ГЛУБОКИЙ АНАЛИЗ IP ОТПРАВИТЕЛЯ
   - IP адрес и reverse DNS
   - Детекция типа инфраструктуры (все флаги ipapi.is):
     * is_bogon (приватный/зарезервированный IP?)
     * is_datacenter (хостинг/дата-центр?)
     * is_mobile (мобильный оператор?)
     * is_satellite (спутниковая связь?)
     * is_crawler (поисковый бот?)
     * is_proxy (прокси-сервер?)
     * is_vpn (VPN-узел?)
     * is_tor (Tor exit node?)
     * is_abuser (история злоупотреблений?)
   - ASN и организация (Amazon, Google, DigitalOcean и т.д.)
   - История в AbuseIPDB, Spamhaus и других RBL
   - Количество жалоб и confidence score

5. РЕПУТАЦИЯ ДОМЕНА
   - Проверка в Spamhaus DBL и других доменных блэклистах
   - Связь с известными мошенническими схемами
   - Авторизация домена (Apple Premium Partner, Microsoft Partner и т.д.)
   - Наличие SSL сертификата и его валидность

6. ПРОВЕРКА СОДЕРЖИМОГО НА ВРЕДОНОСНОСТЬ
   - Анализ всех ссылок в письме (куда ведут, легитимность доменов)
   - Проверка вложений (если есть)
   - Признаки фишинга (запросы данных, угрозы, срочность)
   - Стиль письма и оформление (официальное vs подозрительное)

7. ПРОВЕРКА УТЕЧЕК И КОМПРОМЕТАЦИИ
   - Email отправителя в базах утечек
   - Домен в списках скомпрометированных
   - История инцидентов безопасности

8. ФИНАЛЬНАЯ ОЦЕНКА СОДЕРЖАНИЯ
   - Соответствие контексту (если клиент ожидал письмо)
   - Признаки социальной инженерии
   - Персонализация vs массовая рассылка
   - Юридические элементы (GDPR, условия, контакты)
   - Специфические детали (номера заявок, имена, адреса)

ФОРМАТ ОТВЕТА:

Создай детальный структурированный отчет по каждому разделу. Используй подзаголовки, маркированные списки, конкретные факты и цифры. В конце каждого раздела делай краткий вывод.

После всех разделов предоставь структурированный вердикт в формате:

---ВЕРДИКТ---
[ЛЕГИТИМНОЕ/ПОДОЗРИТЕЛЬНОЕ/ФИШИНГ]

---РИСК---
[green/yellow/red]

---УВЕРЕННОСТЬ---
[0-100]

---НАХОДКИ---
- [Ключевая находка 1]
- [Ключевая находка 2]
- [Ключевая находка 3]
...

---РЕКОМЕНДАЦИИ---
- [Конкретная рекомендация 1]
- [Конкретная рекомендация 2]
- [Конкретная рекомендация 3]
...

ВАЖНО:
- Будь детальным и конкретным в каждом разделе
- Используй все предоставленные технические данные
- Объясняй значение каждого индикатора
- Ищи корреляции между разными факторами
- Не упрощай - давай полную картину"""

    def _build_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build comprehensive prompt for OpenAI with deep research context"""

        # Extract authentication source information
        spf_details = data.get('spf', {})
        dkim_details = data.get('dkim', {})
        dmarc_details = data.get('dmarc', {})

        spf_source = spf_details.get('source', 'self-validated')
        dkim_source = dkim_details.get('source', 'self-validated')
        dmarc_source = dmarc_details.get('source', 'self-validated')

        # Check if using Gmail's validation
        using_gmail_auth = 'gmail' in spf_source.lower() or 'gmail' in dkim_source.lower()

        prompt = f"""Проведи глубокий анализ безопасности электронного письма на основе следующих данных:

═══════════════════════════════════════
📧 ОСНОВНАЯ ИНФОРМАЦИЯ
═══════════════════════════════════════
• Отправитель: {data.get('from_address', 'N/A')} ({data.get('from_name', 'N/A')})
• Тема письма: {data.get('subject', 'N/A')}
• Дата отправки: {data.get('date', 'N/A')}
• Пересланное: {'Да (из .eml вложения)' if data.get('used_eml_attachment') else 'Нет'}

═══════════════════════════════════════
🔐 ПРОВЕРКА ПОДЛИННОСТИ (CRITICAL)
═══════════════════════════════════════
• DKIM валиден: {dkim_details.get('valid', False)} {f'✓ (проверено {dkim_source})' if dkim_details.get('valid') else '✗'}
  - Домен: {dkim_details.get('details', {}).get('domain', 'N/A')}
  - Селектор: {dkim_details.get('details', {}).get('selector', 'N/A')}

• SPF валиден: {spf_details.get('valid', False)} {f'✓ (проверено {spf_source})' if spf_details.get('valid') else '✗'}
  - Результат: {spf_details.get('result', 'N/A')}
  - IP отправителя: {spf_details.get('sender_ip', data.get('sender_ip', 'N/A'))}
  - Домен: {spf_details.get('domain', 'N/A')}

• DMARC найден: {dmarc_details.get('valid', False)} {f'✓ (проверено {dmarc_source})' if dmarc_details.get('valid') else '✗'}
  - Политика: {dmarc_details.get('policy', 'N/A')}
  - Результат: {dmarc_details.get('result', 'N/A')}

⚠️ Источник данных аутентификации: {'Gmail Authentication-Results (высоконадежный)' if using_gmail_auth else 'Собственная проверка'}

═══════════════════════════════════════
🌐 АНАЛИЗ ДОМЕНА
═══════════════════════════════════════
• Домен: {data.get('domain', 'N/A')}
• Возраст домена: {data.get('domain_age_days', 'N/A')} дней {'⚠️ НОВЫЙ ДОМЕН!' if data.get('domain_age_days') and data.get('domain_age_days') < 90 else ''}
• Регистратор: {data.get('registrar', 'N/A')}
• MX записи: {'Найдены ✓' if data.get('mx_records') else 'Отсутствуют ✗'}

WHOIS данные:
{self._format_whois(data.get('whois', {}))}

═══════════════════════════════════════
🌍 ГЛУБОКИЙ АНАЛИЗ IP ОТПРАВИТЕЛЯ
═══════════════════════════════════════
• IP адрес: {data.get('sender_ip', 'N/A')}
• Reverse DNS: {data.get('reverse_dns', 'N/A')}
• Геолокация: {self._format_geolocation(data.get('ip_location', {}))}
• ASN/Организация: {data.get('asn_info', {}).get('name', 'N/A')} ({data.get('asn_info', {}).get('asn', 'N/A')})

ДЕТЕКЦИЯ ТИПА ИНФРАСТРУКТУРЫ (ipapi.is):
{self._format_ip_detailed_flags(data.get('ip_detailed_info', {}))}

РЕПУТАЦИЯ IP:
• В черных списках (RBL): {' ВНИМАНИЕ!' if data.get('ip_blacklisted') else '✓ Нет'}
• Количество RBL: {data.get('blacklist_count', 0)} {'⚠️' if data.get('blacklist_count', 0) > 0 else ''}
• Блэклисты: {', '.join([bl for bl, listed in data.get('blacklist_details', {}).items() if listed]) if data.get('blacklist_details') else 'Нет'}

═══════════════════════════════════════
🌐 АНАЛИЗ ВЕБ-САЙТА
═══════════════════════════════════════
• Сайт существует: {' ✓' if data.get('website_exists') else '✗ НЕТ'}
• HTTPS доступен: {' ✓' if data.get('https_accessible') else '✗'}
• SSL сертификат: {'✓ Валиден' if data.get('ssl_valid') else '✗ Невалиден/отсутствует'}
• Срок действия SSL: {data.get('ssl_days_left', 'N/A')} дней
• CMS/Технологии: {data.get('cms', 'N/A')}

═══════════════════════════════════════
🔍 OSINT И РЕПУТАЦИЯ
═══════════════════════════════════════
• Email в утечках данных: {'⚠️ ДА - email скомпрометирован' if data.get('email_in_breaches') else '✓ Нет'}
• Социальные профили: {'Найдены' if data.get('social_profiles_found') else 'Не найдены'}
• Одноразовый email: {'⚠️ ДА' if data.get('is_disposable') else '✓ Нет'}
• Бесплатный провайдер: {'Да' if data.get('is_free_provider') else 'Нет'}

═══════════════════════════════════════
📊 ЗАДАНИЕ ДЛЯ ГЛУБОКОГО АНАЛИЗА
═══════════════════════════════════════

Проведи всесторонний анализ и ответь в следующем формате:

---ВЕРДИКТ---
[ЛЕГИТИМНОЕ/ПОДОЗРИТЕЛЬНОЕ/ФИШИНГ]

---РИСК---
[green/yellow/red]

---УВЕРЕННОСТЬ---
[0-100]

---НАХОДКИ---
- [Критическая находка 1]
- [Критическая находка 2]
- [Критическая находка 3]
- [Дополнительная находка 4]
- [Дополнительная находка 5]

---РЕКОМЕНДАЦИИ---
- [Конкретная рекомендация 1]
- [Конкретная рекомендация 2]
- [Конкретная рекомендация 3]

---АНАЛИЗ---
[Здесь предоставь ГЛУБОКИЙ ДЕТАЛЬНЫЙ АНАЛИЗ:

1. ОЦЕНКА АУТЕНТИФИКАЦИИ
   - Детальный анализ SPF/DKIM/DMARC
   - Выявленные несоответствия
   - Надежность источника данных

2. АНАЛИЗ ИНФРАСТРУКТУРЫ
   - Оценка домена и его истории
   - Анализ IP и геолокации
   - Репутация инфраструктуры

3. ТЕХНИЧЕСКИЕ ИНДИКАТОРЫ
   - Выявленные аномалии
   - Подозрительные паттерны
   - Корреляция данных

4. ОЦЕНКА УГРОЗ
   - Похожие известные кампании
   - Тактики злоумышленников (если применимо)
   - Потенциальные векторы атаки

5. ИТОГОВОЕ ЗАКЛЮЧЕНИЕ
   - Взвешенная оценка всех факторов
   - Обоснование финального вердикта
   - Критические моменты для принятия решения]

ВАЖНО:
- Анализируй КРИТИЧЕСКИ, не принимай данные на веру
- Один "зеленый" показатель не отменяет множество "красных"
- Обращай внимание на несоответствия между разными источниками
- Будь особенно бдителен к targeted attacks против конкретных организаций
"""

        return prompt

    def _format_whois(self, whois: Dict[str, Any]) -> str:
        """Format WHOIS data for prompt"""
        if not whois:
            return "  Недоступно"

        parts = []
        if whois.get('org'):
            parts.append(f"  • Организация: {whois['org']}")
        if whois.get('country'):
            parts.append(f"  • Страна: {whois['country']}")
        if whois.get('creation_date'):
            parts.append(f"  • Дата создания: {whois['creation_date']}")
        if whois.get('registrar'):
            parts.append(f"  • Регистратор: {whois['registrar']}")

        return "\n".join(parts) if parts else "  Недоступно"

    def _format_geolocation(self, geo: Dict[str, Any]) -> str:
        """Format geolocation data for prompt"""
        if not geo:
            return "Недоступно"

        parts = []
        if geo.get('city'):
            parts.append(geo['city'])
        if geo.get('country'):
            parts.append(geo['country'])
        if geo.get('isp'):
            parts.append(f"(ISP: {geo['isp']})")

        return ", ".join(parts) if parts else "Недоступно"

    def _format_ip_detailed_flags(self, detailed: Dict[str, Any]) -> str:
        """Format detailed IP flags for prompt (ipapi.is style)"""
        if not detailed:
            return "  Недоступно"

        flags = []
        flags.append(f"  • is_bogon (приватный IP): {'⚠️ ДА' if detailed.get('is_bogon') else '✓ Нет'}")
        flags.append(f"  • is_datacenter (хостинг/ЦОД): {'⚠️ ДА' if detailed.get('is_datacenter') else '✓ Нет'}")
        flags.append(f"  • is_mobile (мобильный): {'ДА' if detailed.get('is_mobile') else '✓ Нет'}")
        flags.append(f"  • is_satellite (спутник): {'⚠️ ДА' if detailed.get('is_satellite') else '✓ Нет'}")
        flags.append(f"  • is_crawler (бот): {'ДА' if detailed.get('is_crawler') else '✓ Нет'}")
        flags.append(f"  • is_proxy (прокси): {'⚠️ ДА' if detailed.get('is_proxy') else '✓ Нет'}")
        flags.append(f"  • is_vpn (VPN): {'⚠️ ДА' if detailed.get('is_vpn') else '✓ Нет'}")
        flags.append(f"  • is_tor (Tor): {'⚠️ ДА' if detailed.get('is_tor') else '✓ Нет'}")
        flags.append(f"  • is_abuser (история абуза): {'⚠️ ДА' if detailed.get('is_abuser') else '✓ Нет'}")

        if detailed.get('usage_type'):
            flags.append(f"  • Тип использования: {detailed['usage_type']}")
        if detailed.get('abuse_reports', 0) > 0:
            flags.append(f"  • Жалобы на абуз: {detailed['abuse_reports']} (score: {detailed.get('abuse_score', 0)}%)")

        return "\n".join(flags)

    def _extract_verdict(self, analysis_text: str) -> Dict[str, Any]:
        """Extract structured data from OpenAI's response"""
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
            logger.error(f"Failed to parse OpenAI response: {e}")

        return result

    def generate_summary(self, analysis_data: Dict[str, Any], language: str = 'ru') -> str:
        """
        Generate a concise HTML summary for email response

        Args:
            analysis_data: Analysis results with AI verdict
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

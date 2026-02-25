from fpdf import FPDF
from datetime import datetime
from typing import Dict, Any
from src.utils.logger import logger
import os


class UnicodePDF(FPDF):
    """Extended FPDF with Unicode support"""

    def header(self):
        """Page header"""
        if hasattr(self, 'unicode_font_loaded') and self.unicode_font_loaded:
            self.set_font('DejaVu', '', 14)
            self.cell(0, 10, 'Отчет проверки Email', 0, 1, 'C')
        else:
            self.set_font('Arial', '', 14)
            self.cell(0, 10, 'Email Security Report', 0, 1, 'C')
        self.ln(3)

    def footer(self):
        """Page footer"""
        if hasattr(self, 'unicode_font_loaded') and self.unicode_font_loaded:
            self.set_font('DejaVu', '', 8)
        else:
            self.set_font('Arial', '', 8)
        self.set_y(-15)
        self.cell(0, 10, f'Страница {self.page_no()}/{{nb}}', 0, 0, 'C')


class PDFGenerator:
    """Generate PDF reports for email analysis with Unicode support"""

    def __init__(self):
        pass

    def _set_font_safe(self, pdf: FPDF, font: str, style: str, size: int):
        """
        Safely set font with style, falling back to regular if bold not available

        Args:
            pdf: PDF object
            font: Font name
            style: Font style ('B' for bold, '' for regular)
            size: Font size
        """
        # For built-in fonts (Arial), bold always works
        if font == 'Arial':
            pdf.set_font(font, style, size)
        # For custom fonts (DejaVu), check if bold is loaded
        elif font == 'DejaVu':
            if style == 'B' and hasattr(pdf, 'unicode_font_bold_loaded') and pdf.unicode_font_bold_loaded:
                pdf.set_font(font, 'B', size)
            else:
                # Fall back to regular font if bold not available
                pdf.set_font(font, '', size)
        else:
            pdf.set_font(font, style, size)

    def _ensure_space(self, pdf: FPDF, required_height: int = 40):
        """
        Ensure there's enough space on the page, add new page if not

        Args:
            pdf: PDF object
            required_height: Minimum required height in mm
        """
        # Get current Y position and page height
        current_y = pdf.get_y()
        page_height = pdf.h - pdf.b_margin  # Page height minus bottom margin

        # If not enough space, add a new page
        if current_y + required_height > page_height:
            pdf.add_page()

    def _render_analysis_with_bold_sections(self, pdf: FPDF, text: str, font: str):
        """
        Render analysis text with numbered sections in bold

        Args:
            pdf: PDF object
            text: Text to render
            font: Font to use
        """
        import re

        # Split text into lines
        lines = text.split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                pdf.ln(3)
                continue

            # Check if line starts with a number followed by a period and uppercase text
            # Pattern: "1. WHOIS И ВОЗРАСТ ДОМЕНА" or "10. SOMETHING"
            match = re.match(r'^(\d+)\.\s+([А-ЯЁA-Z][А-ЯЁA-Z\s]+)', line)

            if match:
                # This is a numbered section header - make it bold
                self._set_font_safe(pdf, font, 'B', 9)
                pdf.multi_cell(0, 5, line)
                pdf.ln(1)
            else:
                # Regular text
                pdf.set_font(font, '', 9)
                pdf.multi_cell(0, 5, line)
                pdf.ln(1)

    def _format_domain_age(self, age_days: int, use_russian: bool = True) -> str:
        """
        Format domain age in human-readable format

        Args:
            age_days: Age in days
            use_russian: Use Russian or English labels

        Returns:
            Formatted age string
        """
        if age_days is None:
            return 'N/A'

        if age_days < 30:
            # Less than 30 days - show only days
            return f"{age_days} дней" if use_russian else f"{age_days} days"

        years = age_days // 365
        remaining_days = age_days % 365
        months = remaining_days // 30
        days = remaining_days % 30

        def pluralize_ru(n, one, few, many):
            """Russian pluralization rules"""
            if n % 10 == 1 and n % 100 != 11:
                return one
            if 2 <= n % 10 <= 4 and (n % 100 < 10 or n % 100 >= 20):
                return few
            return many

        if years > 0:
            # Show years and months
            if use_russian:
                year_str = f"{years} {pluralize_ru(years, 'год', 'года', 'лет')}"
                if months > 0:
                    month_str = f"{months} {pluralize_ru(months, 'месяц', 'месяца', 'месяцев')}"
                    return f"{year_str} {month_str} ({age_days} дней)"
                else:
                    return f"{year_str} ({age_days} дней)"
            else:
                year_str = f"{years} year" if years == 1 else f"{years} years"
                if months > 0:
                    month_str = f"{months} month" if months == 1 else f"{months} months"
                    return f"{year_str} {month_str} ({age_days} days)"
                else:
                    return f"{year_str} ({age_days} days)"
        else:
            # Show only months
            if use_russian:
                month_str = f"{months} {pluralize_ru(months, 'месяц', 'месяца', 'месяцев')}"
                return f"{month_str} ({age_days} дней)"
            else:
                month_str = f"{months} month" if months == 1 else f"{months} months"
                return f"{month_str} ({age_days} days)"

    def generate_report(self, analysis_data: Dict[str, Any], output_path: str) -> bool:
        """
        Generate comprehensive PDF report with Cyrillic support

        Args:
            analysis_data: Complete analysis results
            output_path: Path to save PDF

        Returns:
            True if successful, False otherwise
        """
        try:
            pdf = UnicodePDF()
            pdf.unicode_font_loaded = False

            # Try to load DejaVu font for Cyrillic support
            # Get project root directory
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

            font_paths = [
                os.path.join(project_root, 'fonts', 'DejaVuSans.ttf'),
                '/System/Library/Fonts/Supplemental/DejaVuSans.ttf',
                '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                '/Library/Fonts/DejaVuSans.ttf',
            ]

            bold_font_paths = [
                os.path.join(project_root, 'fonts', 'DejaVuSans-Bold.ttf'),
                '/System/Library/Fonts/Supplemental/DejaVuSans-Bold.ttf',
                '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
                '/Library/Fonts/DejaVuSans-Bold.ttf',
            ]

            for font_path in font_paths:
                if os.path.exists(font_path):
                    try:
                        pdf.add_font('DejaVu', '', font_path, uni=True)
                        pdf.unicode_font_loaded = True
                        logger.info(f"Loaded DejaVu font for Cyrillic support from {font_path}")

                        # Try to load bold variant
                        for bold_path in bold_font_paths:
                            if os.path.exists(bold_path):
                                try:
                                    pdf.add_font('DejaVu', 'B', bold_path, uni=True)
                                    pdf.unicode_font_bold_loaded = True
                                    logger.info(f"Loaded DejaVu Bold font from {bold_path}")
                                    break
                                except Exception as e:
                                    logger.warning(f"Failed to load bold font from {bold_path}: {e}")

                        if not hasattr(pdf, 'unicode_font_bold_loaded'):
                            pdf.unicode_font_bold_loaded = False
                            logger.warning("DejaVu Bold font not found, will use regular font for bold text")

                        break
                    except Exception as e:
                        logger.warning(f"Failed to load font from {font_path}: {e}")

            if not pdf.unicode_font_loaded:
                logger.warning("DejaVu font not found, using default fonts - Cyrillic may not display correctly")
                pdf.unicode_font_bold_loaded = False

            pdf.add_page()

            # Title page
            self._create_title_page(pdf, analysis_data)

            # Executive summary
            self._create_executive_summary(pdf, analysis_data)

            # Visual risk bar
            self._draw_risk_bar(pdf, analysis_data.get('overall_score', 0), analysis_data)

            # Score breakdown table
            self._create_score_breakdown(pdf, analysis_data)

            # Detailed sections
            self._create_authentication_section(pdf, analysis_data)
            self._create_domain_section(pdf, analysis_data)
            self._create_ip_section(pdf, analysis_data)
            self._create_website_section(pdf, analysis_data)
            self._create_osint_section(pdf, analysis_data)
            self._create_content_analysis_section(pdf, analysis_data)
            self._create_virustotal_section(pdf, analysis_data)
            self._create_ai_analysis_section(pdf, analysis_data)

            # Output PDF
            pdf.output(output_path)

            logger.info(f"PDF report generated successfully: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def _draw_risk_bar(self, pdf: FPDF, score: int, data: Dict[str, Any]):
        """Draw a visual score bar (0-100)"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'

        bar_x = 10
        bar_y = pdf.get_y() + 2
        bar_width = 190
        bar_height = 8

        # Background (gray)
        pdf.set_fill_color(220, 220, 220)
        pdf.rect(bar_x, bar_y, bar_width, bar_height, 'F')

        # Score fill (color based on score)
        if score >= 75:
            pdf.set_fill_color(40, 167, 69)   # Green
        elif score >= 45:
            pdf.set_fill_color(255, 193, 7)    # Yellow
        else:
            pdf.set_fill_color(220, 53, 69)    # Red

        fill_width = max(1, bar_width * score / 100)
        pdf.rect(bar_x, bar_y, fill_width, bar_height, 'F')

        # Border
        pdf.set_draw_color(100, 100, 100)
        pdf.rect(bar_x, bar_y, bar_width, bar_height, 'D')

        # Score text centered on bar
        pdf.set_font(font, '', 8)
        pdf.set_text_color(0, 0, 0)
        pdf.set_xy(bar_x, bar_y)
        label = f'Оценка доверия: {score}/100' if pdf.unicode_font_loaded else f'Trust Score: {score}/100'
        pdf.cell(bar_width, bar_height, label, 0, 0, 'C')
        pdf.set_y(bar_y + bar_height + 5)

    def _create_score_breakdown(self, pdf: FPDF, data: Dict[str, Any]):
        """Create a category-by-category score table"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        breakdown = data.get('score_breakdown', {})
        weights = data.get('score_weights', {})

        if not breakdown:
            return

        self._ensure_space(pdf, 60)

        title = 'ДЕТАЛИЗАЦИЯ ОЦЕНКИ' if pdf.unicode_font_loaded else 'SCORE BREAKDOWN'
        self._set_font_safe(pdf, font, 'B', 11)
        pdf.cell(0, 8, title, 0, 1)
        pdf.ln(2)

        category_names_ru = {
            'authentication': 'Аутентификация (DKIM/SPF/DMARC)',
            'content': 'Содержимое письма',
            'domain': 'Домен',
            'ip': 'IP отправителя',
            'virustotal': 'VirusTotal',
            'website': 'Веб-сайт',
            'osint': 'OSINT / репутация',
        }
        category_names_en = {
            'authentication': 'Authentication',
            'content': 'Content Analysis',
            'domain': 'Domain',
            'ip': 'Sender IP',
            'virustotal': 'VirusTotal',
            'website': 'Website',
            'osint': 'OSINT / Reputation',
        }
        names = category_names_ru if pdf.unicode_font_loaded else category_names_en

        # Table header
        pdf.set_fill_color(240, 240, 240)
        self._set_font_safe(pdf, font, 'B', 9)
        col1, col2, col3, col4 = 85, 25, 20, 30
        pdf.cell(col1, 6, 'Категория' if pdf.unicode_font_loaded else 'Category', 1, 0, 'L', True)
        pdf.cell(col2, 6, 'Оценка' if pdf.unicode_font_loaded else 'Score', 1, 0, 'C', True)
        pdf.cell(col3, 6, 'Вес' if pdf.unicode_font_loaded else 'Wt', 1, 0, 'C', True)
        pdf.cell(col4, 6, 'Вклад' if pdf.unicode_font_loaded else 'Impact', 1, 1, 'C', True)

        pdf.set_font(font, '', 9)
        for cat in ['authentication', 'content', 'domain', 'ip', 'virustotal', 'website', 'osint']:
            score = breakdown.get(cat, 0)
            weight = weights.get(cat, 0)
            contribution = score * weight / 100

            name = names.get(cat, cat)

            # Color code the score
            if score >= 70:
                pdf.set_text_color(40, 167, 69)
            elif score >= 40:
                pdf.set_text_color(200, 150, 0)
            else:
                pdf.set_text_color(220, 53, 69)

            pdf.cell(col1, 6, name, 1, 0, 'L')
            pdf.cell(col2, 6, f'{score}', 1, 0, 'C')
            pdf.set_text_color(0, 0, 0)
            pdf.cell(col3, 6, f'{weight}%', 1, 0, 'C')
            pdf.cell(col4, 6, f'{contribution:.1f}', 1, 1, 'C')

        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

    def _create_content_analysis_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create content analysis section in PDF"""
        content = data.get('content_analysis', {})
        if not content:
            return

        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        title = '5.5 АНАЛИЗ СОДЕРЖИМОГО' if pdf.unicode_font_loaded else '5.5 CONTENT ANALYSIS'

        self._ensure_space(pdf, 50)
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        risk_score = content.get('content_risk_score', 0)
        risk_label = 'Оценка риска содержимого' if pdf.unicode_font_loaded else 'Content Risk Score'
        self._add_info_row(pdf, risk_label, f'{risk_score}/100')

        urgency = content.get('urgency_indicators', {})
        urgency_label = 'Индикаторы срочности' if pdf.unicode_font_loaded else 'Urgency Indicators'
        self._add_info_row(pdf, urgency_label, str(urgency.get('count', 0)))

        creds = content.get('credential_requests', {})
        creds_label = 'Запросы учётных данных' if pdf.unicode_font_loaded else 'Credential Requests'
        creds_val = ('Обнаружены' if pdf.unicode_font_loaded else 'Detected') if creds.get('detected') else ('Нет' if pdf.unicode_font_loaded else 'No')
        self._add_info_row(pdf, creds_label, creds_val)

        threats = content.get('threat_language', {})
        threats_label = 'Язык угроз' if pdf.unicode_font_loaded else 'Threat Language'
        threats_val = ('Обнаружен' if pdf.unicode_font_loaded else 'Detected') if threats.get('detected') else ('Нет' if pdf.unicode_font_loaded else 'No')
        self._add_info_row(pdf, threats_label, threats_val)

        sus_urls = content.get('suspicious_urls', {})
        total_sus = sus_urls.get('total', 0)
        urls_label = 'Подозрительные ссылки' if pdf.unicode_font_loaded else 'Suspicious URLs'
        self._add_info_row(pdf, urls_label, str(total_sus))

        # Show details if suspicious items found
        if urgency.get('patterns'):
            pdf.ln(2)
            pdf.set_font(font, '', 8)
            detail_label = 'Найденные паттерны срочности: ' if pdf.unicode_font_loaded else 'Urgency patterns: '
            pdf.multi_cell(0, 4, detail_label + ', '.join(urgency['patterns'][:5]))

        if sus_urls.get('ip_based') or sus_urls.get('shortened') or sus_urls.get('mismatched_href'):
            pdf.ln(1)
            pdf.set_font(font, '', 8)
            for ip_url in sus_urls.get('ip_based', [])[:3]:
                pdf.multi_cell(0, 4, f'  IP-URL: {ip_url[:80]}')
            for short_url in sus_urls.get('shortened', [])[:3]:
                pdf.multi_cell(0, 4, f'  Short URL: {short_url[:80]}')
            for mismatch in sus_urls.get('mismatched_href', [])[:3]:
                pdf.multi_cell(0, 4, f'  Mismatch: {mismatch.get("display", "?")} -> {mismatch.get("actual", "?")}')

        homograph = content.get('homograph_attack', {})
        if homograph.get('detected'):
            pdf.ln(1)
            pdf.set_font(font, '', 8)
            pdf.set_text_color(220, 53, 69)
            hg_warn = 'ВНИМАНИЕ: Обнаружена атака гомоглифов!' if pdf.unicode_font_loaded else 'WARNING: Homograph attack detected!'
            pdf.cell(0, 5, hg_warn, 0, 1)
            pdf.set_text_color(0, 0, 0)

        pdf.ln(3)

    def _create_title_page(self, pdf: FPDF, data: Dict[str, Any]):
        """Create title page"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'

        # AI Provider title
        ai_provider = data.get('ai_provider', 'AI')
        ai_names_ru = {
            'perplexity': 'Perplexity AI',
            'claude': 'Claude AI',
            'openai': 'OpenAI GPT'
        }
        ai_names_en = {
            'perplexity': 'Perplexity AI',
            'claude': 'Claude AI',
            'openai': 'OpenAI GPT'
        }
        ai_name = ai_names_ru.get(ai_provider.lower(), 'AI') if pdf.unicode_font_loaded else ai_names_en.get(ai_provider.lower(), 'AI')

        title_text = f'Отчёт проверки Email через {ai_name}' if pdf.unicode_font_loaded else f'Email Verification Report via {ai_name}'

        self._set_font_safe(pdf, font, 'B', 16)
        pdf.cell(0, 12, title_text, 0, 1, 'C')
        pdf.ln(8)

        # Basic info
        date_label = 'Дата проверки:' if pdf.unicode_font_loaded else 'Check Date:'
        from_label = 'От кого:' if pdf.unicode_font_loaded else 'From:'
        sender_name_label = 'Имя отправителя:' if pdf.unicode_font_loaded else 'Sender Name:'
        to_label = 'Кому:' if pdf.unicode_font_loaded else 'To:'
        subject_label = 'Тема:' if pdf.unicode_font_loaded else 'Subject:'

        pdf.set_font(font, '', 10)
        pdf.cell(45, 7, date_label, 0, 0)
        pdf.cell(0, 7, datetime.now().strftime('%d.%m.%Y %H:%M:%S'), 0, 1)

        pdf.set_font(font, '', 10)
        pdf.cell(45, 7, from_label, 0, 0)
        pdf.cell(0, 7, data.get('from_address', 'N/A')[:80], 0, 1)

        pdf.set_font(font, '', 10)
        pdf.cell(45, 7, sender_name_label, 0, 0)
        sender_name = data.get('from_name', '').strip()
        if not sender_name:
            sender_name = 'нет информации' if pdf.unicode_font_loaded else 'no information'
        pdf.cell(0, 7, sender_name[:80], 0, 1)

        pdf.set_font(font, '', 10)
        pdf.cell(45, 7, to_label, 0, 0)
        pdf.cell(0, 7, data.get('to_address', 'N/A')[:80], 0, 1)

        pdf.set_font(font, '', 10)
        pdf.cell(45, 7, subject_label, 0, 0)
        subject = data.get('subject', 'N/A')[:80]
        pdf.cell(0, 7, subject, 0, 1)

        pdf.ln(5)

    def _create_executive_summary(self, pdf: FPDF, data: Dict[str, Any]):
        """Create executive summary"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'

        summary_title = 'РЕЗЮМЕ АНАЛИЗА' if pdf.unicode_font_loaded else 'ANALYSIS SUMMARY'
        verdict_label = 'Вердикт:' if pdf.unicode_font_loaded else 'Verdict:'
        ai_label = 'AI система:' if pdf.unicode_font_loaded else 'AI System:'
        confidence_label = 'Уверенность:' if pdf.unicode_font_loaded else 'Confidence:'
        risk_label = 'Уровень риска:' if pdf.unicode_font_loaded else 'Risk Level:'

        # Title with background
        pdf.set_fill_color(240, 240, 240)
        self._set_font_safe(pdf, font, 'B', 14)
        pdf.cell(0, 10, summary_title, 0, 1, 'C', True)
        pdf.ln(5)

        # Verdict
        self._set_font_safe(pdf, font, 'B', 10)
        pdf.cell(35, 7, verdict_label, 0, 0)
        pdf.set_font(font, '', 10)
        verdict = data.get('verdict', 'Невозможно определить' if pdf.unicode_font_loaded else 'Unable to determine')[:120]
        pdf.cell(0, 7, verdict, 0, 1)

        # Risk Level (if available)
        risk_level = data.get('risk_level', '').upper()
        if risk_level:
            risk_colors = {'GREEN': (0, 150, 0), 'YELLOW': (200, 150, 0), 'RED': (200, 0, 0)}
            risk_names_ru = {'GREEN': 'Низкий (Зелёный)', 'YELLOW': 'Средний (Жёлтый)', 'RED': 'Высокий (Красный)'}
            risk_names_en = {'GREEN': 'Low (Green)', 'YELLOW': 'Medium (Yellow)', 'RED': 'High (Red)'}

            self._set_font_safe(pdf, font, 'B', 10)
            pdf.cell(35, 7, risk_label, 0, 0)
            pdf.set_font(font, '', 10)

            color = risk_colors.get(risk_level, (0, 0, 0))
            pdf.set_text_color(*color)
            risk_name = risk_names_ru.get(risk_level, risk_level) if pdf.unicode_font_loaded else risk_names_en.get(risk_level, risk_level)
            pdf.cell(0, 7, risk_name, 0, 1)
            pdf.set_text_color(0, 0, 0)  # Reset to black

        # Confidence Score (if available)
        confidence = data.get('confidence')
        if confidence is not None:
            self._set_font_safe(pdf, font, 'B', 10)
            pdf.cell(35, 7, confidence_label, 0, 0)
            pdf.set_font(font, '', 10)
            pdf.cell(0, 7, f'{confidence}%', 0, 1)

        # AI Provider
        ai_provider = data.get('ai_provider', 'unknown')
        ai_provider_names = {
            'perplexity': 'Perplexity AI (Sonar Pro)',
            'claude': 'Anthropic Claude',
            'openai': 'OpenAI GPT'
        }
        ai_name = ai_provider_names.get(ai_provider.lower(), ai_provider.upper())
        self._set_font_safe(pdf, font, 'B', 10)
        pdf.cell(35, 7, ai_label, 0, 0)
        pdf.set_font(font, '', 10)
        pdf.cell(0, 7, ai_name, 0, 1)

        # Overall score
        overall_score = data.get('overall_score')
        if overall_score is not None:
            score_label = 'Общая оценка:' if pdf.unicode_font_loaded else 'Overall Score:'
            self._set_font_safe(pdf, font, 'B', 10)
            pdf.cell(35, 7, score_label, 0, 0)
            pdf.set_font(font, '', 10)
            pdf.cell(0, 7, f'{overall_score}/100', 0, 1)

        # Risk disagreement warning
        if data.get('risk_disagreement'):
            pdf.ln(2)
            pdf.set_font(font, '', 9)
            pdf.set_text_color(200, 100, 0)
            ai_risk = (data.get('ai_original_risk') or '').upper()
            score_risk = (data.get('score_original_risk') or '').upper()
            if pdf.unicode_font_loaded:
                warning = f'Внимание: AI оценка ({ai_risk}) расходится с технической ({score_risk}). Использована более осторожная.'
            else:
                warning = f'Warning: AI assessment ({ai_risk}) disagrees with technical ({score_risk}). Using more cautious.'
            pdf.multi_cell(0, 5, warning)
            pdf.set_text_color(0, 0, 0)

        pdf.ln(5)

    def _create_email_info_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create email information section"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        title = '1. ИНФОРМАЦИЯ О ПИСЬМЕ' if pdf.unicode_font_loaded else '1. EMAIL INFORMATION'

        # Section header with underline
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        labels = {
            'from': 'От кого' if pdf.unicode_font_loaded else 'From',
            'sender_name': 'Имя отправителя' if pdf.unicode_font_loaded else 'Sender Name',
            'to': 'Кому' if pdf.unicode_font_loaded else 'To',
            'subject': 'Тема' if pdf.unicode_font_loaded else 'Subject'
        }

        self._add_info_row(pdf, labels['from'], data.get('from_address', 'N/A'))
        self._add_info_row(pdf, labels['sender_name'], data.get('from_name', 'N/A'))
        self._add_info_row(pdf, labels['to'], data.get('to_address', 'N/A'))
        self._add_info_row(pdf, labels['subject'], data.get('subject', 'N/A'))

        pdf.ln(3)

    def _create_authentication_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create authentication section"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        title = '1. ПРОВЕРКА ПОДЛИННОСТИ' if pdf.unicode_font_loaded else '1. AUTHENTICATION'

        # Section header with underline
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        # DKIM
        dkim = data.get('dkim', {})
        if pdf.unicode_font_loaded:
            dkim_status = 'Валиден' if dkim.get('valid') else 'Не валиден'
        else:
            dkim_status = 'Valid' if dkim.get('valid') else 'Invalid'
        self._add_info_row(pdf, 'DKIM', dkim_status)

        # SPF
        spf = data.get('spf', {})
        if pdf.unicode_font_loaded:
            spf_status = 'Валиден' if spf.get('valid') else 'Не валиден'
        else:
            spf_status = 'Valid' if spf.get('valid') else 'Invalid'
        self._add_info_row(pdf, 'SPF', spf_status)

        # DMARC
        dmarc = data.get('dmarc', {})
        dmarc_result = dmarc.get('result', 'unknown')
        if pdf.unicode_font_loaded:
            if dmarc_result == 'pass':
                dmarc_status = 'Прошел проверку (PASS)'
            elif dmarc_result == 'fail':
                dmarc_status = 'Не прошел проверку (FAIL)'
            elif dmarc_result == 'none':
                dmarc_status = 'Не проверялся'
            elif not dmarc.get('checked', True):
                dmarc_status = 'Не проверялся'
            else:
                dmarc_status = 'Не найден' if not dmarc.get('valid') else 'Найден'
        else:
            if dmarc_result == 'pass':
                dmarc_status = 'Pass'
            elif dmarc_result == 'fail':
                dmarc_status = 'Fail'
            elif dmarc_result == 'none':
                dmarc_status = 'Not checked'
            elif not dmarc.get('checked', True):
                dmarc_status = 'Not checked'
            else:
                dmarc_status = 'Not found' if not dmarc.get('valid') else 'Found'
        self._add_info_row(pdf, 'DMARC', dmarc_status)

        pdf.ln(3)

    def _create_domain_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create domain analysis section"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        title = '2. АНАЛИЗ ДОМЕНА' if pdf.unicode_font_loaded else '2. DOMAIN ANALYSIS'

        # Section header with underline
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        domain_label = 'Домен' if pdf.unicode_font_loaded else 'Domain'
        age_label = 'Возраст домена' if pdf.unicode_font_loaded else 'Domain Age'
        registrar_label = 'Регистратор' if pdf.unicode_font_loaded else 'Registrar'

        self._add_info_row(pdf, domain_label, data.get('domain', 'N/A'))
        domain_age = data.get('domain_age_days')
        age_str = self._format_domain_age(domain_age, use_russian=pdf.unicode_font_loaded)
        self._add_info_row(pdf, age_label, age_str)
        self._add_info_row(pdf, registrar_label, data.get('registrar', 'N/A'))

        pdf.ln(3)

    def _create_ip_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create IP analysis section"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        title = '3. АНАЛИЗ IP ОТПРАВИТЕЛЯ' if pdf.unicode_font_loaded else '3. IP ANALYSIS'

        # Section header with underline
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        ip_label = 'IP адрес' if pdf.unicode_font_loaded else 'IP Address'
        geo_label = 'Геолокация' if pdf.unicode_font_loaded else 'Geolocation'
        blacklist_label = 'В черных списках' if pdf.unicode_font_loaded else 'Blacklisted'

        self._add_info_row(pdf, ip_label, data.get('sender_ip', 'N/A'))

        ip_loc = data.get('ip_location', {})
        if ip_loc:
            location_str = f"{ip_loc.get('city', 'N/A')}, {ip_loc.get('country', 'N/A')}"
            self._add_info_row(pdf, geo_label, location_str)

        blacklist_status = ('Да' if pdf.unicode_font_loaded else 'Yes') if data.get('ip_blacklisted') else ('Нет' if pdf.unicode_font_loaded else 'No')
        self._add_info_row(pdf, blacklist_label, blacklist_status)

        pdf.ln(3)

    def _create_website_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create website analysis section"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        title = '4. АНАЛИЗ САЙТА' if pdf.unicode_font_loaded else '4. WEBSITE ANALYSIS'

        # Ensure enough space for the section
        self._ensure_space(pdf, 35)

        # Section header with underline
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        exists_label = 'Сайт существует' if pdf.unicode_font_loaded else 'Website Exists'
        ssl_label = 'SSL валиден' if pdf.unicode_font_loaded else 'SSL Valid'

        exists = ('Да' if pdf.unicode_font_loaded else 'Yes') if data.get('website_exists') else ('Нет' if pdf.unicode_font_loaded else 'No')
        self._add_info_row(pdf, exists_label, exists)

        ssl_valid = ('Да' if pdf.unicode_font_loaded else 'Yes') if data.get('ssl_valid') else ('Нет' if pdf.unicode_font_loaded else 'No')
        self._add_info_row(pdf, ssl_label, ssl_valid)

        pdf.ln(3)

    def _create_osint_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create OSINT section"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        title = '5. OSINT ДАННЫЕ' if pdf.unicode_font_loaded else '5. OSINT DATA'

        # Section header with underline
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        breaches_label = 'Email в утечках' if pdf.unicode_font_loaded else 'Found in Breaches'
        disposable_label = 'Одноразовый email' if pdf.unicode_font_loaded else 'Disposable Email'

        breaches = ('Да' if pdf.unicode_font_loaded else 'Yes') if data.get('email_in_breaches') else ('Нет' if pdf.unicode_font_loaded else 'No')
        self._add_info_row(pdf, breaches_label, breaches)

        disposable = ('Да' if pdf.unicode_font_loaded else 'Yes') if data.get('is_disposable') else ('Нет' if pdf.unicode_font_loaded else 'No')
        self._add_info_row(pdf, disposable_label, disposable)

        pdf.ln(3)

    def _create_virustotal_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create VirusTotal analysis section"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'

        if not data.get('virustotal_enabled'):
            return

        title = '6. VIRUSTOTAL СКАНИРОВАНИЕ' if pdf.unicode_font_loaded else '6. VIRUSTOTAL SCAN'

        # Section header with underline
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(2)

        # Attachments
        attachments = data.get('virustotal_attachments', [])
        if attachments:
            att_title = 'Вложения:' if pdf.unicode_font_loaded else 'Attachments:'
            # Use bold only for Arial, not for DejaVu (bold font not loaded)
            self._set_font_safe(pdf, font, 'B', 10)
            pdf.cell(0, 6, att_title, 0, 1)
            pdf.set_font(font, '', 9)

            for att in attachments:
                if att.get('scanned'):
                    detections = att.get('detections', 0)
                    total = att.get('total_scanners', 0)
                    filename = att.get('filename', 'Unknown')

                    # Truncate long filenames
                    display_filename = filename[:60] + '...' if len(filename) > 60 else filename

                    if detections > 0:
                        # Malicious file - red warning
                        pdf.set_text_color(220, 53, 69)  # Red
                        status = f"{detections}/{total} обнаружений" if pdf.unicode_font_loaded else f"⚠ {detections}/{total} detections"
                    else:
                        # Clean file - green
                        pdf.set_text_color(40, 167, 69)  # Green
                        status = f"Чисто ({total} сканеров)" if pdf.unicode_font_loaded else f"✓ Clean ({total} scanners)"

                    # Print filename and status on separate lines to avoid overflow
                    pdf.multi_cell(0, 5, f"  {display_filename}")
                    # Use cell() instead of multi_cell() for short status text
                    pdf.cell(0, 5, status, 0, 1)
                    pdf.set_text_color(0, 0, 0)  # Reset to black
                else:
                    pdf.multi_cell(0, 5, f"  {att.get('filename')}: {att.get('error', 'Scan failed')}")

            pdf.ln(2)

        # URLs
        urls = data.get('virustotal_urls', [])
        if urls:
            url_title = 'Ссылки в письме:' if pdf.unicode_font_loaded else 'URLs in email:'
            # Use bold only for Arial, not for DejaVu (bold font not loaded)
            self._set_font_safe(pdf, font, 'B', 10)
            pdf.cell(0, 6, url_title, 0, 1)
            pdf.set_font(font, '', 9)

            for url_data in urls:
                if url_data.get('scanned'):
                    detections = url_data.get('detections', 0)
                    total = url_data.get('total_scanners', 0)
                    url = url_data.get('url', 'Unknown')

                    # Truncate long URLs
                    display_url = url[:80] + '...' if len(url) > 80 else url

                    if detections > 0:
                        # Malicious URL - red warning
                        pdf.set_text_color(220, 53, 69)  # Red
                        status = f"{detections}/{total} обнаружений" if pdf.unicode_font_loaded else f"⚠ {detections}/{total} detections"
                    else:
                        # Clean URL - green
                        pdf.set_text_color(40, 167, 69)  # Green
                        status = f"Чисто ({total} сканеров)" if pdf.unicode_font_loaded else f"✓ Clean ({total})"

                    pdf.multi_cell(0, 5, f"  {display_url}")
                    # Use cell() instead of multi_cell() for short status text
                    pdf.cell(0, 5, status, 0, 1)
                    pdf.set_text_color(0, 0, 0)  # Reset to black
                else:
                    pdf.multi_cell(0, 5, f"  {url_data.get('url', 'Unknown')}: {url_data.get('error', 'Scan failed')}")

            pdf.ln(2)

        if not attachments and not urls:
            no_data = 'Вложения и ссылки не найдены' if pdf.unicode_font_loaded else 'No attachments or URLs found'
            pdf.set_font(font, '', 10)
            pdf.cell(0, 6, no_data, 0, 1)

        pdf.ln(3)

    def _create_ai_analysis_section(self, pdf: FPDF, data: Dict[str, Any]):
        """Create AI analysis section"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        import re

        # Ensure enough space for the section
        self._ensure_space(pdf, 50)

        # Get AI provider name
        ai_provider = data.get('ai_provider', 'unknown')
        ai_provider_short = {
            'perplexity': 'PERPLEXITY',
            'claude': 'CLAUDE',
            'openai': 'GPT'
        }
        provider_name = ai_provider_short.get(ai_provider.lower(), ai_provider.upper())

        if pdf.unicode_font_loaded:
            title = f'7. РАСШИРЕННЫЙ АНАЛИЗ AI ({provider_name})'
        else:
            title = f'7. EXTENDED AI ANALYSIS ({provider_name})'

        # Section header with underline
        self._set_font_safe(pdf, font, 'B', 12)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        # Extract deep analysis from full_analysis (remove structured sections)
        deep_analysis = ""
        if data.get('full_analysis'):
            full_text = data['full_analysis']
            # Extract only the ---АНАЛИЗ--- section
            analysis_match = re.search(r'---АНАЛИЗ---\s*\n(.+?)(?=\n---|\Z)', full_text, re.DOTALL)
            if analysis_match:
                deep_analysis = analysis_match.group(1).strip()
            else:
                # If no structured format, use full text
                deep_analysis = full_text

        # 1. РЕКОМЕНДАЦИИ (with emoji)
        if data.get('recommendations'):
            # Ensure enough space for recommendations section
            self._ensure_space(pdf, 30)

            rec_title = '👉🏻 РЕКОМЕНДАЦИИ:' if pdf.unicode_font_loaded else '👉🏻 RECOMMENDATIONS:'
            self._set_font_safe(pdf, font, 'B', 11)
            pdf.cell(0, 8, rec_title, 0, 1)
            pdf.set_font(font, '', 9)
            pdf.ln(2)

            for rec in data.get('recommendations', []):
                # Remove ** formatting
                clean_rec = rec.replace('**', '')
                pdf.multi_cell(0, 5, f'  • {clean_rec}')
                pdf.ln(1)
            pdf.ln(4)

        # 2. ГЛУБОКИЙ АНАЛИЗ (with emoji)
        if deep_analysis:
            analysis_title = '👉🏻 ГЛУБОКИЙ АНАЛИЗ:' if pdf.unicode_font_loaded else '👉🏻 DEEP ANALYSIS:'
            self._set_font_safe(pdf, font, 'B', 11)
            pdf.cell(0, 8, analysis_title, 0, 1)
            pdf.ln(2)

            # Clean and display analysis with bold subsections
            clean_analysis = deep_analysis.replace('**', '').strip()
            self._render_analysis_with_bold_sections(pdf, clean_analysis, font)
            pdf.ln(4)

        # 3. ВЫВОД (with emoji) - extract from verdict and risk
        verdict = data.get('verdict', 'Невозможно определить')
        risk_level = data.get('risk_level', 'yellow').upper()
        confidence = data.get('confidence', 0)

        conclusion_title = '👉🏻 ВЫВОД:' if pdf.unicode_font_loaded else '👉🏻 CONCLUSION:'
        self._set_font_safe(pdf, font, 'B', 11)
        pdf.cell(0, 8, conclusion_title, 0, 1)
        pdf.set_font(font, '', 9)
        pdf.ln(2)

        if pdf.unicode_font_loaded:
            risk_names = {'GREEN': 'НИЗКИЙ', 'YELLOW': 'СРЕДНИЙ', 'RED': 'ВЫСОКИЙ'}
            risk_name = risk_names.get(risk_level, risk_level)
            conclusion = f'На основании проведённого анализа, письмо классифицировано как "{verdict}" с уровнем риска {risk_name}. Уверенность в оценке составляет {confidence}%. '

            if risk_level == 'RED':
                conclusion += 'Настоятельно рекомендуется не взаимодействовать с этим письмом.'
            elif risk_level == 'YELLOW':
                conclusion += 'Рекомендуется соблюдать осторожность и проверить отправителя дополнительными способами.'
            else:
                conclusion += 'Письмо выглядит легитимным, однако всегда следует сохранять бдительность.'
        else:
            risk_names = {'GREEN': 'LOW', 'YELLOW': 'MEDIUM', 'RED': 'HIGH'}
            risk_name = risk_names.get(risk_level, risk_level)
            conclusion = f'Based on the analysis, the email is classified as "{verdict}" with {risk_name} risk level. Confidence score is {confidence}%. '

            if risk_level == 'RED':
                conclusion += 'It is strongly recommended not to interact with this email.'
            elif risk_level == 'YELLOW':
                conclusion += 'Exercise caution and verify the sender through additional means.'
            else:
                conclusion += 'The email appears legitimate, but always remain vigilant.'

        pdf.multi_cell(0, 5, conclusion)
        pdf.ln(3)

    def _add_info_row(self, pdf: FPDF, label: str, value: str):
        """Add an information row"""
        font = 'DejaVu' if pdf.unicode_font_loaded else 'Arial'
        pdf.set_font(font, '', 9)
        pdf.cell(45, 6, label + ':', 0, 0)
        pdf.set_font(font, '', 9)

        # Handle long values
        value_str = str(value)[:100]  # Limit length
        pdf.cell(0, 6, value_str, 0, 1)

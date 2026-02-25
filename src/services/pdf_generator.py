from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
from typing import Dict, Any
import os
from src.utils.logger import logger


class PDFGenerator:
    """Generate PDF reports for email analysis"""

    def __init__(self):
        self.page_size = A4
        self.styles = getSampleStyleSheet()
        self._register_fonts()
        self._setup_custom_styles()

    def _register_fonts(self):
        """Register Unicode fonts for Cyrillic support"""
        # Use Times New Roman which has better Unicode support in PDF
        pass

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=1  # Center
        ))

        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceBefore=20,
            spaceAfter=12,
            borderWidth=1,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5,
            leftIndent=10
        ))

        # Risk indicator style
        self.styles.add(ParagraphStyle(
            name='RiskIndicator',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=14,
            spaceAfter=10,
            alignment=1
        ))

        # Update Normal style for Cyrillic
        self.styles['Normal'].fontName = 'Helvetica'
        self.styles['Normal'].fontSize = 10

    def generate_report(self, analysis_data: Dict[str, Any], output_path: str) -> bool:
        """
        Generate comprehensive PDF report

        Args:
            analysis_data: Complete analysis results
            output_path: Path to save PDF

        Returns:
            True if successful, False otherwise
        """
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=self.page_size,
                rightMargin=2*cm,
                leftMargin=2*cm,
                topMargin=2*cm,
                bottomMargin=2*cm
            )

            # Build content
            story = []

            # Title page
            story.extend(self._create_title_page(analysis_data))

            # Executive summary
            story.extend(self._create_executive_summary(analysis_data))
            story.append(PageBreak())

            # Detailed sections
            story.extend(self._create_email_info_section(analysis_data))
            story.extend(self._create_authentication_section(analysis_data))
            story.extend(self._create_domain_section(analysis_data))
            story.extend(self._create_ip_section(analysis_data))
            story.extend(self._create_website_section(analysis_data))
            story.extend(self._create_osint_section(analysis_data))
            story.extend(self._create_ai_analysis_section(analysis_data))

            # Build PDF
            doc.build(story)

            logger.info(f"PDF report generated successfully: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return False

    def _create_title_page(self, data: Dict[str, Any]) -> list:
        """Create title page"""
        content = []

        # Title
        title = Paragraph("ОТЧЕТ ПРОВЕРКИ EMAIL", self.styles['CustomTitle'])
        content.append(title)
        content.append(Spacer(1, 1*cm))

        # Risk indicator with emoji
        risk_level = data.get('risk_level', 'yellow')
        risk_emoji = {'green': '🟢', 'yellow': '🟡', 'red': '🔴'}.get(risk_level, '🟡')
        risk_text = {
            'green': 'БЕЗОПАСНО',
            'yellow': 'ТРЕБУЕТ ВНИМАНИЯ',
            'red': 'ОПАСНО'
        }.get(risk_level, 'НЕИЗВЕСТНО')

        risk_para = Paragraph(
            f'<font size="32">{risk_emoji}</font><br/><br/>'
            f'<b>{risk_text}</b>',
            self.styles['RiskIndicator']
        )
        content.append(risk_para)
        content.append(Spacer(1, 1*cm))

        # Basic info table
        basic_info = [
            ['Оценка достоверности:', f"{data.get('overall_score', 0)}/100"],
            ['Дата проверки:', datetime.now().strftime('%d.%m.%Y %H:%M:%S')],
            ['От кого:', data.get('from_address', 'N/A')],
            ['Тема:', data.get('subject', 'N/A')[:100]]
        ]

        table = Table(basic_info, colWidths=[6*cm, 10*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        content.append(table)
        content.append(PageBreak())

        return content

    def _create_executive_summary(self, data: Dict[str, Any]) -> list:
        """Create executive summary"""
        content = []

        content.append(Paragraph("РЕЗЮМЕ", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.5*cm))

        # Verdict
        verdict = data.get('verdict', 'Невозможно определить')
        content.append(Paragraph(f"<b>Вердикт:</b> {verdict}", self.styles['Normal']))
        content.append(Spacer(1, 0.3*cm))

        # Key findings
        if data.get('key_findings'):
            content.append(Paragraph("<b>Ключевые находки:</b>", self.styles['Normal']))
            for finding in data.get('key_findings', []):
                content.append(Paragraph(f"• {finding}", self.styles['Normal']))
            content.append(Spacer(1, 0.3*cm))

        # Recommendations
        if data.get('recommendations'):
            content.append(Paragraph("<b>Рекомендации:</b>", self.styles['Normal']))
            for rec in data.get('recommendations', []):
                content.append(Paragraph(f"• {rec}", self.styles['Normal']))

        content.append(Spacer(1, 0.5*cm))

        return content

    def _create_email_info_section(self, data: Dict[str, Any]) -> list:
        """Create email information section"""
        content = []

        content.append(Paragraph("1. ИНФОРМАЦИЯ О ПИСЬМЕ", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.3*cm))

        email_info = [
            ['От кого', data.get('from_address', 'N/A')],
            ['Имя отправителя', data.get('from_name', 'N/A')],
            ['Кому', data.get('to_address', 'N/A')],
            ['Тема', data.get('subject', 'N/A')],
            ['Дата письма', str(data.get('date', 'N/A'))],
            ['Message-ID', data.get('message_id', 'N/A')[:60]]
        ]

        table = self._create_info_table(email_info)
        content.append(table)
        content.append(Spacer(1, 0.5*cm))

        return content

    def _create_authentication_section(self, data: Dict[str, Any]) -> list:
        """Create authentication section"""
        content = []

        content.append(Paragraph("2. ПРОВЕРКА ПОДЛИННОСТИ", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.3*cm))

        # DKIM
        dkim = data.get('dkim', {})
        dkim_status = '✓ Валиден' if dkim.get('valid') else '✗ Не валиден'
        dkim_color = colors.green if dkim.get('valid') else colors.red

        # SPF
        spf = data.get('spf', {})
        spf_status = '✓ Валиден' if spf.get('valid') else '✗ Не валиден'
        spf_color = colors.green if spf.get('valid') else colors.red

        # DMARC
        dmarc = data.get('dmarc', {})
        dmarc_result = dmarc.get('result', 'unknown')
        if dmarc_result == 'pass':
            dmarc_status = '✓ Прошел проверку (PASS)'
            dmarc_color = colors.green
        elif dmarc_result == 'fail':
            dmarc_status = '✗ Не прошел (FAIL)'
            dmarc_color = colors.red
        elif dmarc_result == 'none' or not dmarc.get('checked', True):
            dmarc_status = '○ Не проверялся'
            dmarc_color = colors.grey
        else:
            dmarc_status = '✗ Не найден' if not dmarc.get('valid') else '✓ Найден'
            dmarc_color = colors.green if dmarc.get('valid') else colors.orange

        auth_info = [
            ['Проверка', 'Статус', 'Детали'],
            ['DKIM', dkim_status, dkim.get('signature', 'N/A')[:40]],
            ['SPF', spf_status, spf.get('result', 'N/A')],
            ['DMARC', dmarc_status, dmarc.get('policy', 'N/A')]
        ]

        table = Table(auth_info, colWidths=[4*cm, 4*cm, 8*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        content.append(table)
        content.append(Spacer(1, 0.5*cm))

        return content

    def _create_domain_section(self, data: Dict[str, Any]) -> list:
        """Create domain analysis section"""
        content = []

        content.append(Paragraph("3. АНАЛИЗ ДОМЕНА", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.3*cm))

        domain_info = [
            ['Домен', data.get('domain', 'N/A')],
            ['Возраст домена', f"{data.get('domain_age_days', 'N/A')} дней"],
            ['Регистратор', data.get('registrar', 'N/A')],
            ['MX записи', str(len(data.get('mx_records', [])))],
            ['Одноразовый домен', 'Да' if data.get('is_disposable') else 'Нет']
        ]

        table = self._create_info_table(domain_info)
        content.append(table)
        content.append(Spacer(1, 0.5*cm))

        return content

    def _create_ip_section(self, data: Dict[str, Any]) -> list:
        """Create IP analysis section"""
        content = []

        content.append(Paragraph("4. АНАЛИЗ IP ОТПРАВИТЕЛЯ", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.3*cm))

        ip_loc = data.get('ip_location', {})
        location_str = f"{ip_loc.get('city', 'N/A')}, {ip_loc.get('country', 'N/A')}"

        ip_info = [
            ['IP адрес', data.get('sender_ip', 'N/A')],
            ['Геолокация', location_str],
            ['ISP/Провайдер', ip_loc.get('isp', 'N/A')],
            ['В черных списках', 'Да ✗' if data.get('ip_blacklisted') else 'Нет ✓'],
            ['Количество blacklist', str(data.get('blacklist_count', 0))],
            ['Прокси/VPN', 'Да' if data.get('is_proxy') else 'Нет']
        ]

        table = self._create_info_table(ip_info)
        content.append(table)
        content.append(Spacer(1, 0.5*cm))

        return content

    def _create_website_section(self, data: Dict[str, Any]) -> list:
        """Create website analysis section"""
        content = []

        content.append(Paragraph("5. АНАЛИЗ САЙТА", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.3*cm))

        website_info = [
            ['Сайт существует', 'Да' if data.get('website_exists') else 'Нет'],
            ['HTTPS доступен', 'Да ✓' if data.get('https_accessible') else 'Нет ✗'],
            ['SSL валиден', 'Да ✓' if data.get('ssl_valid') else 'Нет ✗'],
            ['SSL истекает через', f"{data.get('ssl_days_left', 'N/A')} дней"],
            ['CMS/Платформа', data.get('cms', 'N/A')]
        ]

        table = self._create_info_table(website_info)
        content.append(table)
        content.append(Spacer(1, 0.5*cm))

        return content

    def _create_osint_section(self, data: Dict[str, Any]) -> list:
        """Create OSINT section"""
        content = []

        content.append(Paragraph("6. OSINT ДАННЫЕ", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.3*cm))

        osint_info = [
            ['Email в утечках', 'Да ✗' if data.get('email_in_breaches') else 'Нет ✓'],
            ['Социальные профили', 'Найдены' if data.get('social_profiles_found') else 'Не найдены'],
            ['Одноразовый email', 'Да ✗' if data.get('is_disposable') else 'Нет ✓'],
            ['Бесплатный провайдер', 'Да' if data.get('is_free_provider') else 'Нет']
        ]

        table = self._create_info_table(osint_info)
        content.append(table)
        content.append(Spacer(1, 0.5*cm))

        return content

    def _create_ai_analysis_section(self, data: Dict[str, Any]) -> list:
        """Create AI analysis section"""
        content = []

        content.append(Paragraph("7. АНАЛИЗ ИСКУССТВЕННОГО ИНТЕЛЛЕКТА (CLAUDE)", self.styles['SectionHeader']))
        content.append(Spacer(1, 0.3*cm))

        # Full analysis
        if data.get('claude_analysis'):
            analysis_text = data['claude_analysis'].replace('\n', '<br/>')
            content.append(Paragraph(analysis_text, self.styles['Normal']))

        content.append(Spacer(1, 0.5*cm))

        return content

    def _create_info_table(self, data: list) -> Table:
        """Create a formatted info table"""
        table = Table(data, colWidths=[6*cm, 10*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        return table

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import Optional, List
from config.config import config
from src.utils.logger import logger


class EmailService:
    """Service for sending email reports"""

    def __init__(self):
        self.smtp_host = config.SMTP_HOST
        self.smtp_port = config.SMTP_PORT
        self.smtp_user = config.SMTP_USER
        self.smtp_password = config.SMTP_PASSWORD
        self.from_address = config.SMTP_FROM

    def send_report(
        self,
        to_address: str,
        subject: str,
        body: str,
        pdf_path: Optional[str] = None,
        original_email_path: Optional[str] = None
    ) -> bool:
        """
        Send email report with PDF attachment

        Args:
            to_address: Recipient email
            subject: Email subject
            body: Email body (text or HTML)
            pdf_path: Path to PDF report
            original_email_path: Path to original .eml file

        Returns:
            True if successful, False otherwise
        """
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_address
            msg['To'] = to_address
            msg['Subject'] = subject

            # Add body
            msg.attach(MIMEText(body, 'html'))

            # Attach PDF report
            if pdf_path:
                with open(pdf_path, 'rb') as f:
                    pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
                    pdf_attachment.add_header('Content-Disposition', 'attachment', filename='email_analysis_report.pdf')
                    msg.attach(pdf_attachment)

            # Attach original email
            if original_email_path:
                with open(original_email_path, 'rb') as f:
                    eml_attachment = MIMEApplication(f.read(), _subtype='eml')
                    eml_attachment.add_header('Content-Disposition', 'attachment', filename='original_email.eml')
                    msg.attach(eml_attachment)

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            logger.info(f"Report sent successfully to {to_address}")
            return True

        except Exception as e:
            logger.error(f"Failed to send report: {e}")
            return False

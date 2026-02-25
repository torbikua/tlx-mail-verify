#!/usr/bin/env python3
"""
Debug script to see email structure
"""
import sys
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import EmailMessage
from email.parser import BytesParser
from email import policy

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))


def create_test_email_with_rfc822():
    """Create a test email with inline forwarded email (message/rfc822)"""
    # Create wrapper email
    wrapper = MIMEMultipart()
    wrapper['From'] = 'forwarder@example.com'
    wrapper['To'] = 'verifier@example.com'
    wrapper['Subject'] = 'FW: Phishing Attempt'

    # Add body
    body = MIMEText('Check this suspicious email.', 'plain')
    wrapper.attach(body)

    # Create original email as EmailMessage
    original = EmailMessage()
    original['From'] = 'scammer@fake-bank.com'
    original['To'] = 'victim@example.com'
    original['Subject'] = 'Your account has been suspended'
    original['Date'] = 'Tue, 16 Jan 2024 15:45:00 +0000'
    original['Message-ID'] = '<scam456@fake-bank.com>'
    original['Return-Path'] = '<bounce@fake-bank.com>'
    original.add_header('Received', 'from mail.fake-bank.com (mail.fake-bank.com [203.0.113.50]) by mx.google.com')
    original.set_content('Click here to verify your account or it will be deleted.')

    # Attach as message/rfc822
    wrapper.attach(original)

    return wrapper.as_bytes()


def debug_structure():
    test_email = create_test_email_with_rfc822()
    msg = BytesParser(policy=policy.default).parsebytes(test_email)

    print("Email structure:")
    print(f"Content-Type: {msg.get_content_type()}")
    print(f"Is multipart: {msg.is_multipart()}")
    print()

    for i, part in enumerate(msg.walk()):
        print(f"Part {i}:")
        print(f"  Content-Type: {part.get_content_type()}")
        print(f"  Content-Maintype: {part.get_content_maintype()}")
        print(f"  Content-Disposition: {part.get('Content-Disposition', 'None')}")
        print(f"  Filename: {part.get_filename()}")

        if part.get_content_type() == 'message/rfc822':
            print(f"  This is message/rfc822!")
            payload = part.get_payload()
            print(f"  Payload type: {type(payload)}")
            if isinstance(payload, list):
                print(f"  Payload length: {len(payload)}")
                for j, item in enumerate(payload):
                    print(f"    Item {j} type: {type(item)}")
        print()


if __name__ == '__main__':
    debug_structure()

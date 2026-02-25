#!/usr/bin/env python3
"""
Quick script to regenerate PDF for a specific check_id
"""
import sys
import json
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config.config import config
from src.services.pdf_generator_unicode import PDFGenerator
from src.utils.database import db, EmailCheck

def regenerate_pdf(check_id: int):
    """Regenerate PDF for a specific check_id"""
    # Connect to database
    if not db.connect():
        print("❌ Failed to connect to database")
        return False

    # Create database session
    session = db.get_session()

    # Load check record
    check = session.query(EmailCheck).filter_by(id=check_id).first()

    if not check:
        print(f"❌ Check ID {check_id} not found in database")
        return False

    print(f"✅ Found check ID {check_id}: {check.from_address}")
    print(f"   Subject: {check.subject}")
    print(f"   Status: {check.status}")

    # Load analysis data from claude_analysis field
    if not check.claude_analysis:
        print(f"❌ No analysis data found for check ID {check_id}")
        return False

    try:
        analysis_data = json.loads(check.claude_analysis)
        print(f"✅ Loaded analysis data ({len(check.claude_analysis)} bytes)")
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse analysis data: {e}")
        return False

    # Generate PDF
    try:
        pdf_generator = PDFGenerator()
        pdf_path = pdf_generator.generate_pdf(analysis_data, language='ru')
        print(f"✅ PDF generated successfully: {pdf_path}")

        # Update database with new path
        check.report_pdf_path = pdf_path
        session.commit()
        session.close()
        print(f"✅ Database updated with new PDF path")

        return True

    except Exception as e:
        print(f"❌ Failed to generate PDF: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 regenerate_pdf.py <check_id>")
        sys.exit(1)

    check_id = int(sys.argv[1])
    success = regenerate_pdf(check_id)
    sys.exit(0 if success else 1)

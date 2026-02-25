#!/usr/bin/env python3
"""
Clear all email checks from the database
"""
import sys
import os
import glob
from src.utils.database import db, EmailCheck, CheckResult, SystemLog
from src.utils.logger import logger
from config.config import config


def clear_files():
    """Clear all attachment and report files"""
    try:
        # Count files
        attachments = glob.glob(os.path.join(config.ATTACHMENTS_DIR, '*.eml'))
        reports = glob.glob(os.path.join(config.REPORTS_DIR, '*.pdf'))

        logger.info(f"Found {len(attachments)} attachment files")
        logger.info(f"Found {len(reports)} report files")

        if len(attachments) == 0 and len(reports) == 0:
            logger.info("No files to delete")
            return

        # Delete attachments
        if attachments:
            logger.info("Deleting attachment files...")
            for file in attachments:
                try:
                    os.remove(file)
                except Exception as e:
                    logger.warning(f"Failed to delete {file}: {e}")
            logger.info(f"✓ Deleted {len(attachments)} attachment files")

        # Delete reports
        if reports:
            logger.info("Deleting report files...")
            for file in reports:
                try:
                    os.remove(file)
                except Exception as e:
                    logger.warning(f"Failed to delete {file}: {e}")
            logger.info(f"✓ Deleted {len(reports)} report files")

    except Exception as e:
        logger.error(f"Failed to clear files: {e}")


def clear_database(also_clear_files=False):
    """Clear all records from email_checks and check_results tables"""

    # Connect to database
    logger.info("Connecting to database...")
    if not db.connect():
        logger.error("Failed to connect to database. Exiting.")
        sys.exit(1)

    session = db.get_session()

    try:
        # Count records before deletion
        email_checks_count = session.query(EmailCheck).count()
        check_results_count = session.query(CheckResult).count()

        logger.info(f"Found {email_checks_count} email checks")
        logger.info(f"Found {check_results_count} check results")

        # Count files
        attachments_count = len(glob.glob(os.path.join(config.ATTACHMENTS_DIR, '*.eml')))
        reports_count = len(glob.glob(os.path.join(config.REPORTS_DIR, '*.pdf')))

        if email_checks_count == 0 and check_results_count == 0 and attachments_count == 0 and reports_count == 0:
            logger.info("Database and files are already empty")
            return

        # Ask for confirmation
        print(f"\n⚠️  WARNING: This will delete:")
        print(f"   - {email_checks_count} email checks")
        print(f"   - {check_results_count} check results")
        if also_clear_files:
            print(f"   - {attachments_count} attachment files (.eml)")
            print(f"   - {reports_count} report files (.pdf)")
        print(f"\nThis action cannot be undone!\n")

        response = input("Are you sure you want to continue? (yes/no): ")

        if response.lower() != 'yes':
            logger.info("Operation cancelled by user")
            return

        # Delete check_results first (to avoid foreign key issues if they exist)
        logger.info("Deleting check results...")
        deleted_results = session.query(CheckResult).delete()
        session.commit()
        logger.info(f"✓ Deleted {deleted_results} check results")

        # Delete email_checks
        logger.info("Deleting email checks...")
        deleted_checks = session.query(EmailCheck).delete()
        session.commit()
        logger.info(f"✓ Deleted {deleted_checks} email checks")

        # Clear files if requested
        if also_clear_files:
            clear_files()

        logger.info("✓ Database cleared successfully!")

    except Exception as e:
        logger.error(f"Failed to clear database: {e}")
        session.rollback()
        sys.exit(1)
    finally:
        session.close()
        db.close()


if __name__ == '__main__':
    print("="*60)
    print("Mail Address Verifier - Database Cleaner")
    print("="*60)

    # Check command line arguments
    clear_files_flag = '--with-files' in sys.argv or '-f' in sys.argv

    if clear_files_flag:
        print("Mode: Clear database AND files")
    else:
        print("Mode: Clear database only (use --with-files or -f to also clear files)")

    print()
    clear_database(also_clear_files=clear_files_flag)

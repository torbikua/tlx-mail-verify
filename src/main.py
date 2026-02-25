#!/usr/bin/env python3
"""
Mail Address Verifier - Main Application
"""
import sys
import threading
from src.services.imap_service import IMAPService
from src.services.orchestrator import Orchestrator
from src.utils.database import db
from src.utils.logger import logger
from src.web.app import create_app
from config.config import config


def process_emails_callback(emails):
    """Callback for processing fetched emails"""
    orchestrator = Orchestrator()
    imap_service = IMAPService()

    for message_id, raw_email, email_uid in emails:
        try:
            logger.info(f"Processing email: {message_id} (UID: {email_uid})")
            success = orchestrator.process_email(message_id, raw_email)

            # Move to verified folder if processing was successful
            if success:
                imap_service.move_email_to_folder(email_uid)
        except Exception as e:
            logger.error(f"Failed to process email {message_id}: {e}")


def start_imap_monitor():
    """Start IMAP monitoring in background"""
    logger.info("Starting IMAP monitor...")
    imap_service = IMAPService()

    if imap_service.connect():
        imap_service.monitor(process_emails_callback)
    else:
        logger.error("Failed to start IMAP monitor")


def start_web_server():
    """Start web admin interface (localhost only, behind nginx)"""
    logger.info(f"Starting web server on 127.0.0.1:{config.WEB_PORT}...")
    app = create_app()
    app.run(
        host='127.0.0.1',
        port=config.WEB_PORT,
        debug=False
    )


def main():
    """Main application entry point"""
    logger.info("="*60)
    logger.info("Mail Address Verifier - Starting")
    logger.info("="*60)

    # Connect to database
    logger.info("Connecting to database...")
    if not db.connect():
        logger.error("Failed to connect to database. Exiting.")
        sys.exit(1)

    # Create tables if needed
    db.create_tables()

    # Start IMAP monitor in background thread
    imap_thread = threading.Thread(target=start_imap_monitor, daemon=True)
    imap_thread.start()

    # Start web server in main thread
    try:
        start_web_server()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        db.close()
        logger.info("Application stopped")


if __name__ == '__main__':
    main()

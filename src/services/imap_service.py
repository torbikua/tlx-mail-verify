import imaplib
import email
import time
from typing import List, Tuple, Optional
from config.config import config
from src.utils.logger import logger


class IMAPService:
    """IMAP service for monitoring and fetching emails"""

    def __init__(self):
        self.host = config.IMAP_HOST
        self.port = config.IMAP_PORT
        self.user = config.IMAP_USER
        self.password = config.IMAP_PASSWORD
        self.folder = config.IMAP_FOLDER
        self.verified_folder = config.IMAP_VERIFIED_FOLDER
        self.move_to_verified = config.IMAP_MOVE_TO_VERIFIED
        self.check_interval = config.IMAP_CHECK_INTERVAL
        self.connection = None

    def connect(self) -> bool:
        """Connect to IMAP server"""
        try:
            self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            self.connection.login(self.user, self.password)
            logger.info(f"Connected to IMAP server: {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to IMAP: {e}")
            return False

    def disconnect(self):
        """Disconnect from IMAP server"""
        try:
            if self.connection:
                self.connection.logout()
                logger.info("Disconnected from IMAP server")
        except:
            pass

    def fetch_new_emails(self) -> List[Tuple[str, bytes, str]]:
        """
        Fetch new emails based on IMAP_SEARCH_MODE setting

        Returns:
            List of tuples (message_id, raw_email_bytes, email_uid)
        """
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                if not self.connection:
                    if not self.connect():
                        retry_count += 1
                        time.sleep(2)
                        continue

                try:
                    self.connection.select(self.folder)
                except:
                    # Connection lost, reconnect
                    logger.warning("IMAP connection lost, reconnecting...")
                    self.disconnect()
                    self.connection = None
                    if not self.connect():
                        retry_count += 1
                        time.sleep(2)
                        continue
                    self.connection.select(self.folder)

                # Search for emails based on mode
                search_mode = config.IMAP_SEARCH_MODE.lower()
                if search_mode == 'all':
                    search_criteria = 'ALL'
                    logger.debug("Searching for all emails")
                else:
                    search_criteria = '(UNSEEN)'
                    logger.debug("Searching for unseen emails only")

                _, message_numbers = self.connection.search(None, search_criteria)

                emails = []
                for num in message_numbers[0].split():
                    # Fetch both RFC822 and UID
                    _, msg_data = self.connection.fetch(num, '(RFC822 UID)')
                    raw_email = msg_data[0][1]

                    # Extract UID from response - parse properly
                    uid_pattern = msg_data[0][0].decode()
                    # Format is like: "1 (UID 123 RFC822 {1234}"
                    import re
                    uid_match = re.search(r'UID (\d+)', uid_pattern)
                    email_uid = uid_match.group(1) if uid_match else num.decode()

                    # Parse to get message ID
                    msg = email.message_from_bytes(raw_email)
                    message_id = msg.get('Message-ID', '')

                    emails.append((message_id, raw_email, email_uid))

                    logger.info(f"Fetched email: {message_id} (UID: {email_uid})")

                if not emails:
                    logger.debug("No new unseen emails found")

                return emails

            except Exception as e:
                logger.error(f"Failed to fetch emails (attempt {retry_count + 1}/{max_retries}): {e}")
                retry_count += 1

                # Try to reconnect for next attempt
                try:
                    self.disconnect()
                    self.connection = None
                except:
                    pass

                if retry_count < max_retries:
                    time.sleep(2)
                else:
                    return []

        return []

    def ensure_verified_folder(self) -> bool:
        """
        Ensure the verified folder exists, create if it doesn't

        Returns:
            True if folder exists or was created successfully, False otherwise
        """
        try:
            if not self.connection:
                if not self.connect():
                    return False

            # List all folders to check if verified folder exists
            status, folders = self.connection.list()
            if status != 'OK':
                logger.error(f"Failed to list IMAP folders: {status}")
                return False

            # Check if verified folder exists
            folder_exists = False
            for folder in folders:
                # Decode folder name
                folder_str = folder.decode() if isinstance(folder, bytes) else str(folder)
                if self.verified_folder in folder_str:
                    folder_exists = True
                    break

            if not folder_exists:
                # Create verified folder
                logger.info(f"Creating IMAP folder: {self.verified_folder}")
                status, _ = self.connection.create(self.verified_folder)
                if status != 'OK':
                    logger.error(f"Failed to create folder {self.verified_folder}: {status}")
                    return False
                logger.info(f"Successfully created folder: {self.verified_folder}")
            else:
                logger.debug(f"Folder {self.verified_folder} already exists")

            return True

        except Exception as e:
            logger.error(f"Error ensuring verified folder exists: {e}")
            return False

    def move_email_to_folder(self, email_uid: str, target_folder: str = None) -> bool:
        """
        Move email to specified folder (default: verified folder)

        Args:
            email_uid: Email UID to move
            target_folder: Target folder name (defaults to verified_folder)

        Returns:
            True if successful, False otherwise
        """
        if not self.move_to_verified:
            logger.debug("Moving emails is disabled in config")
            return True

        target = target_folder or self.verified_folder

        try:
            if not self.connection:
                if not self.connect():
                    return False

            # Ensure we're in the source folder
            try:
                self.connection.select(self.folder)
            except:
                logger.warning("IMAP connection lost, reconnecting...")
                self.disconnect()
                self.connection = None
                if not self.connect():
                    return False
                self.connection.select(self.folder)

            # Ensure target folder exists
            if not self.ensure_verified_folder():
                logger.error(f"Cannot move email - target folder {target} doesn't exist and couldn't be created")
                return False

            # Copy email to verified folder
            logger.debug(f"Copying email UID {email_uid} to {target}")
            status, _ = self.connection.uid('COPY', email_uid, target)
            if status != 'OK':
                logger.error(f"Failed to copy email UID {email_uid} to {target}: {status}")
                return False

            # Mark original as deleted
            logger.debug(f"Marking email UID {email_uid} as deleted")
            status, _ = self.connection.uid('STORE', email_uid, '+FLAGS', '(\\Deleted)')
            if status != 'OK':
                logger.error(f"Failed to mark email UID {email_uid} as deleted: {status}")
                return False

            # Expunge to permanently remove
            self.connection.expunge()

            logger.info(f"Successfully moved email UID {email_uid} to {target}")
            return True

        except Exception as e:
            logger.error(f"Failed to move email UID {email_uid} to {target}: {e}")
            return False

    def monitor(self, callback):
        """
        Monitor IMAP folder for new emails

        Args:
            callback: Function to call with new emails
        """
        logger.info("Starting IMAP monitoring...")

        while True:
            try:
                emails = self.fetch_new_emails()

                if emails:
                    logger.info(f"Found {len(emails)} new emails to process")
                    callback(emails)

                time.sleep(self.check_interval)

            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait before retry

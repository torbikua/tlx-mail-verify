#!/usr/bin/env python3
"""
Create initial admin user
"""
import sys
from src.utils.database import db, User
from src.utils.logger import logger


def create_admin():
    """Create admin user"""

    # Connect to database
    logger.info("Connecting to database...")
    if not db.connect():
        logger.error("Failed to connect to database. Exiting.")
        sys.exit(1)

    # Create tables
    db.create_tables()

    session = db.get_session()

    try:
        username = input("Enter admin username (default: admin): ").strip() or "admin"
        password = input("Enter admin password: ").strip()

        if not password:
            logger.error("Password cannot be empty")
            sys.exit(1)

        # Check if user exists
        existing = session.query(User).filter_by(username=username).first()
        if existing:
            logger.warning(f"User '{username}' already exists")
            response = input("Do you want to update the password? (yes/no): ")
            if response.lower() == 'yes':
                existing.set_password(password)
                session.commit()
                logger.info(f"✓ Password updated for user '{username}'")
            else:
                logger.info("Operation cancelled")
            return

        # Create new admin user
        user = User(username=username, is_admin=True)
        user.set_password(password)
        session.add(user)
        session.commit()

        logger.info(f"✓ Admin user '{username}' created successfully!")
        print(f"\nYou can now login at http://localhost:8080/admin with:")
        print(f"  Username: {username}")
        print(f"  Password: {password}")

    except Exception as e:
        logger.error(f"Failed to create admin user: {e}")
        session.rollback()
        sys.exit(1)
    finally:
        session.close()
        db.close()


if __name__ == '__main__':
    print("="*60)
    print("Mail Address Verifier - Create Admin User")
    print("="*60)
    print()
    create_admin()

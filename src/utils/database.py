from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, Enum, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime
from config.config import config
from src.utils.logger import logger
import enum
import bcrypt

Base = declarative_base()

class StatusEnum(enum.Enum):
    PENDING = 'pending'
    PROCESSING = 'processing'
    COMPLETED = 'completed'
    FAILED = 'failed'

class RiskLevelEnum(enum.Enum):
    GREEN = 'green'
    YELLOW = 'yellow'
    RED = 'red'

class EmailCheck(Base):
    __tablename__ = 'email_checks'

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Email Info
    message_id = Column(String(512))
    subject = Column(Text)
    from_address = Column(String(512))
    from_name = Column(String(512))
    to_address = Column(String(512))
    received_date = Column(DateTime)

    # Status
    status = Column(Enum(StatusEnum), default=StatusEnum.PENDING)

    # Results
    overall_score = Column(Integer, default=0)
    risk_level = Column(Enum(RiskLevelEnum), nullable=True)

    # Raw Data
    raw_email_path = Column(String(1024))
    report_pdf_path = Column(String(1024))

    # AI Analysis
    claude_analysis = Column(Text)  # Stores full AI analysis text

class CheckResult(Base):
    __tablename__ = 'check_results'

    id = Column(Integer, primary_key=True, autoincrement=True)
    check_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # DKIM/SPF/DMARC
    dkim_valid = Column(Boolean)
    dkim_details = Column(JSON)
    spf_valid = Column(Boolean)
    spf_details = Column(JSON)
    dmarc_valid = Column(Boolean)
    dmarc_details = Column(JSON)

    # Domain Analysis
    domain_whois = Column(JSON)
    domain_age_days = Column(Integer)
    domain_registrar = Column(String(512))
    mx_records = Column(JSON)
    dns_records = Column(JSON)

    # IP Analysis
    sender_ip = Column(String(45))
    ip_location = Column(JSON)
    ip_blacklisted = Column(Boolean)
    ip_blacklist_details = Column(JSON)

    # Website Analysis
    website_exists = Column(Boolean)
    website_ssl_valid = Column(Boolean)
    website_ssl_details = Column(JSON)
    website_content_summary = Column(Text)

    # OSINT
    email_in_breaches = Column(Boolean)
    breach_details = Column(JSON)
    online_mentions = Column(JSON)

    # AI Analysis
    claude_analysis = Column(Text)
    claude_verdict = Column(Text)

class SystemLog(Base):
    __tablename__ = 'system_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    level = Column(String(20))
    component = Column(String(128))
    message = Column(Text)
    details = Column(JSON)

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    username = Column(String(128), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False)

    def set_password(self, password):
        """Set password hash using bcrypt"""
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def check_password(self, password):
        """Check password against bcrypt hash"""
        try:
            return bcrypt.checkpw(password.encode(), self.password_hash.encode())
        except (ValueError, TypeError):
            return False

class Database:
    """Database connection manager"""

    def __init__(self):
        self.engine = None
        self.session_factory = None
        self.Session = None

    def connect(self):
        """Initialize database connection"""
        try:
            self.engine = create_engine(
                config.DATABASE_URL,
                pool_pre_ping=True,
                pool_recycle=3600,
                echo=False
            )
            self.session_factory = sessionmaker(bind=self.engine)
            self.Session = scoped_session(self.session_factory)
            logger.info("Database connection established")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return False

    def create_tables(self):
        """Create all tables"""
        try:
            Base.metadata.create_all(self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")

    def get_session(self):
        """Get a new database session"""
        return self.Session()

    def close(self):
        """Close database connection"""
        if self.Session:
            self.Session.remove()
        if self.engine:
            self.engine.dispose()
        logger.info("Database connection closed")

# Global database instance
db = Database()

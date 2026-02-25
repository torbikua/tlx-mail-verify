import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables with override to ensure fresh values
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(dotenv_path=env_path, override=True)

def load_analysis_prompt():
    """Load analysis prompt from .env or external file"""
    # Try loading from .env first
    prompt = os.getenv('ANALYSIS_PROMPT_TEMPLATE', '').strip()

    # If empty or failed to parse from .env, load from external file
    if not prompt:
        prompt_file = Path(__file__).parent / 'analysis_prompt.txt'
        if prompt_file.exists():
            prompt = prompt_file.read_text(encoding='utf-8')

    return prompt

class Config:
    """Application configuration"""

    # IMAP Settings
    IMAP_HOST = os.getenv('IMAP_HOST')
    IMAP_PORT = int(os.getenv('IMAP_PORT', 993))
    IMAP_USER = os.getenv('IMAP_USER')
    IMAP_PASSWORD = os.getenv('IMAP_PASSWORD')
    IMAP_FOLDER = os.getenv('IMAP_FOLDER', 'INBOX')
    IMAP_CHECK_INTERVAL = int(os.getenv('IMAP_CHECK_INTERVAL', 60))
    IMAP_SEARCH_MODE = os.getenv('IMAP_SEARCH_MODE', 'unseen')  # 'all' or 'unseen'
    IMAP_VERIFIED_FOLDER = os.getenv('IMAP_VERIFIED_FOLDER', 'Verified')  # Folder for processed emails
    IMAP_MOVE_TO_VERIFIED = os.getenv('IMAP_MOVE_TO_VERIFIED', 'true').lower() == 'true'  # Move emails after processing

    # SMTP Settings
    SMTP_HOST = os.getenv('SMTP_HOST')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USER = os.getenv('SMTP_USER')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    SMTP_FROM = os.getenv('SMTP_FROM')

    # Database Settings
    USE_SQLITE = os.getenv('USE_SQLITE', 'false').lower() == 'true'
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_NAME = os.getenv('DB_NAME', 'mail_verifier')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD')

    @property
    def DATABASE_URL(self):
        if self.USE_SQLITE:
            return f"sqlite:///{self.BASE_DIR}/data/mail_verifier.db"
        return f"mysql+mysqlconnector://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    # AI API Configuration
    AI_PROVIDER = os.getenv('AI_PROVIDER', 'claude')  # 'openai', 'claude', or 'perplexity'

    # Perplexity API
    PERPLEXITY_API_KEY = os.getenv('PERPLEXITY_API_KEY')
    PERPLEXITY_MODEL = os.getenv('PERPLEXITY_MODEL', 'sonar-pro')
    PERPLEXITY_MAX_TOKENS = int(os.getenv('PERPLEXITY_MAX_TOKENS', 4000))
    PERPLEXITY_ANALYSIS_PROMPT = os.getenv('PERPLEXITY_ANALYSIS_PROMPT', '')

    # Claude API
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
    CLAUDE_MODEL = os.getenv('CLAUDE_MODEL', 'claude-3-5-sonnet-20241022')
    CLAUDE_MAX_TOKENS = int(os.getenv('CLAUDE_MAX_TOKENS', 4000))

    # API Ninjas
    API_NINJAS_API_KEY = os.getenv('API_NINJAS_API_KEY')

    # VirusTotal API
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

    # OpenAI API
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4-turbo-preview')  # or 'o1-preview' for deep reasoning
    OPENAI_MAX_TOKENS = int(os.getenv('OPENAI_MAX_TOKENS', 4000))
    OPENAI_TEMPERATURE = float(os.getenv('OPENAI_TEMPERATURE', 0.3))
    OPENAI_API_TIMEOUT = int(os.getenv('OPENAI_API_TIMEOUT', 300))  # API timeout in seconds (default: 5 minutes)

    # Deep Research Mode
    OPENAI_DEEP_RESEARCH = os.getenv('OPENAI_DEEP_RESEARCH', 'true').lower() == 'true'
    OPENAI_RESEARCH_STEPS = int(os.getenv('OPENAI_RESEARCH_STEPS', 1))  # Number of analysis passes

    # Custom Analysis Prompt (can be overridden in .env or loaded from file)
    ANALYSIS_PROMPT_TEMPLATE = load_analysis_prompt()

    # Web Admin
    WEB_HOST = os.getenv('WEB_HOST', '0.0.0.0')
    WEB_PORT = int(os.getenv('WEB_PORT', 8080))
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme')
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24).hex())

    # Application Settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 5))
    REPORT_LANGUAGE = os.getenv('REPORT_LANGUAGE', 'ru')
    TIMEZONE = os.getenv('TIMEZONE', 'Europe/Moscow')

    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    ATTACHMENTS_DIR = os.path.join(DATA_DIR, 'attachments')
    REPORTS_DIR = os.path.join(DATA_DIR, 'reports')

    # Risk scoring thresholds
    RISK_GREEN_THRESHOLD = 70  # >= 70 = green
    RISK_YELLOW_THRESHOLD = 40  # 40-69 = yellow, < 40 = red

config = Config()

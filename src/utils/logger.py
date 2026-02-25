import logging
import sys
from datetime import datetime
from pathlib import Path
from colorlog import ColoredFormatter
from config.config import config

class Logger:
    """Centralized logging system"""

    _instances = {}

    def __new__(cls, name='mail_verifier'):
        if name not in cls._instances:
            cls._instances[name] = super(Logger, cls).__new__(cls)
            cls._instances[name]._initialized = False
        return cls._instances[name]

    def __init__(self, name='mail_verifier'):
        if self._initialized:
            return

        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, config.LOG_LEVEL))

        # Create logs directory if not exists
        Path(config.LOGS_DIR).mkdir(parents=True, exist_ok=True)

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)

        console_formatter = ColoredFormatter(
            '%(log_color)s%(asctime)s - %(name)s - %(levelname)s%(reset)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
        console_handler.setFormatter(console_formatter)

        # File handler
        log_file = Path(config.LOGS_DIR) / f'mail_verifier_{datetime.now().strftime("%Y%m%d")}.log'
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)

        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)

        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

        self._initialized = True

    def debug(self, message, **kwargs):
        self.logger.debug(message, extra=kwargs)

    def info(self, message, **kwargs):
        self.logger.info(message, extra=kwargs)

    def warning(self, message, **kwargs):
        self.logger.warning(message, extra=kwargs)

    def error(self, message, **kwargs):
        self.logger.error(message, extra=kwargs)

    def critical(self, message, **kwargs):
        self.logger.critical(message, extra=kwargs)

# Global logger instance
logger = Logger()

import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    DATABASE_PATH = os.getenv(
        "DATABASE_PATH", os.path.join(BASE_DIR, "instance", "app.db")
    )
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + DATABASE_PATH
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "60"))
    MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))
    WTF_CSRF_ENABLED = False

    # Email configuration
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "false").lower() == "true" or int(os.getenv("MAIL_PORT", "587")) == 465
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv(
        "MAIL_DEFAULT_SENDER",
        f"Web Checker <{MAIL_USERNAME}>" if MAIL_USERNAME else "noreply@webchecker.local",
    )
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
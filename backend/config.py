import os
import tempfile
from pydantic_settings import BaseSettings

# On Vercel / serverless environments, use system temp directory for writeable SQLite database
default_db_path = "sqlite:///./security_monitor.db"
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    default_db_path = f"sqlite:///{tempfile.gettempdir()}/security_monitor.db"

class Settings(BaseSettings):
    APP_NAME: str = "Cloud Security Monitoring & Threat Detection System"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", default_db_path)
    
    # Security / JWT
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-cloud-security-threat-detector-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120
    
    # Intrusion Detection Thresholds
    BRUTE_FORCE_THRESHOLD: int = 5            # 5 failed logins
    BRUTE_FORCE_WINDOW_MINUTES: int = 5       # within 5 minutes
    HIGH_REQUEST_RATE_THRESHOLD: int = 50     # 50 requests
    HIGH_REQUEST_WINDOW_MINUTES: int = 1      # within 1 minute

    class Config:
        env_file = ".env"

settings = Settings()

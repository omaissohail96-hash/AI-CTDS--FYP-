from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberGuard AI SaaS"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "SUPER_SECRET_KEY_REPLACE_IN_PRODUCTION"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7 # 7 days
    
    # Database
    # Using SQLite locally for easier team testing, can be swapped for PostgreSQL
    DATABASE_URL: str = "sqlite:///./cyberguard.db"
    
    class Config:
        case_sensitive = True

settings = Settings()

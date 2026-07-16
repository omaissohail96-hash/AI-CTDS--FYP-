import os
from typing import Dict, List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Application ─────────────────────────────────────────────────────────
    PROJECT_NAME: str = "CyberGuard AI SaaS"
    API_V1_STR: str = "/api/v1"
    VERSION: str = "2.2.0"

    # ── Security / JWT ───────────────────────────────────────────────────────
    SECRET_KEY: str = "SUPER_SECRET_KEY_REPLACE_IN_PRODUCTION"
    REFRESH_SECRET_KEY: str = "REFRESH_SECRET_KEY_REPLACE_IN_PRODUCTION"
    CSRF_SECRET_KEY: str = "CSRF_SECRET_KEY_REPLACE_IN_PRODUCTION"

    # Access token: short-lived (15 min default)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    # Refresh token: long-lived (7 days default)
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    # Cookie settings
    COOKIE_SECURE: bool = False       # Set True in production (HTTPS only)
    COOKIE_SAMESITE: str = "lax"      # "strict" | "lax" | "none"
    COOKIE_HTTPONLY: bool = True
    COOKIE_DOMAIN: str = ""           # Empty = current domain

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cyberguard.db")
    # PostgreSQL connection pool settings (ignored for SQLite)
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_PRE_PING: bool = True

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_ENABLED: bool = False       # Set True when Redis is available
    REDIS_SOCKET_TIMEOUT: float = 1.0
    REDIS_SOCKET_CONNECT_TIMEOUT: float = 1.0

    # Cache TTLs (seconds)
    CACHE_TTL_BLOCKED_ENTITY: int = 300      # 5 min
    CACHE_TTL_THREAT_INTEL: int = 300        # 5 min
    CACHE_TTL_UBA_PROFILE: int = 600         # 10 min
    CACHE_TTL_API_KEY: int = 900             # 15 min
    CACHE_TTL_WORKSPACE_QUOTA: int = 60      # 1 min

    # ── Celery ───────────────────────────────────────────────────────────────
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    CELERY_ENABLED: bool = False      # Set True when Celery workers are running

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Comma-separated list of allowed origins. Use "*" ONLY in local dev.
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:5174,http://localhost:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    # ── Trusted Reverse Proxies ───────────────────────────────────────────────
    # Comma-separated list of trusted proxy IPs/CIDRs.
    # Only these sources may set X-Forwarded-For / X-Real-IP.
    TRUSTED_PROXIES: str = ""

    @property
    def trusted_proxies_list(self) -> List[str]:
        return [p.strip() for p in self.TRUSTED_PROXIES.split(",") if p.strip()]

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT_RPM: int = 120      # Requests per minute per IP
    RATE_LIMIT_SCAN_RPM: int = 30          # Stricter limit for scan endpoints
    RATE_LIMIT_AUTH_RPM: int = 10          # Strictest limit for auth endpoints
    RATE_LIMIT_BURST: int = 20             # Burst allowance above RPM

    # ── Risk Scoring Engine ───────────────────────────────────────────────────
    # Ensemble weights — must sum to 1.0
    RISK_WEIGHT_ML: float = 0.40
    RISK_WEIGHT_THREAT_INTEL: float = 0.25
    RISK_WEIGHT_CORRELATION: float = 0.20
    RISK_WEIGHT_UBA: float = 0.15

    @property
    def risk_weights(self) -> Dict[str, float]:
        weights = {
            "ml": self.RISK_WEIGHT_ML,
            "threat_intel": self.RISK_WEIGHT_THREAT_INTEL,
            "correlation": self.RISK_WEIGHT_CORRELATION,
            "uba": self.RISK_WEIGHT_UBA,
        }
        total = sum(weights.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Risk weights must sum to 1.0, got {total}")
        return weights

    # ── False Positive Prevention ─────────────────────────────────────────────
    # ML confidence alone is never enough to trigger a block
    FP_ML_ONLY_BLOCK: bool = False
    # Minimum ML confidence score to count as a "high" signal
    FP_ML_HIGH_THRESHOLD: int = 85
    # Number of independent detections required for multi-signal block
    FP_MULTI_SIGNAL_COUNT: int = 2
    # Hours window for repeated detection counting
    FP_REPEATED_DETECTION_WINDOW_HOURS: int = 24
    # Number of repeated malicious detections before allowing block
    FP_REPEATED_DETECTION_COUNT: int = 3
    # Risk score above which an entity goes to human review queue
    FP_REVIEW_QUEUE_THRESHOLD: int = 70

    # ── Security Headers ──────────────────────────────────────────────────────
    SECURITY_HEADERS_ENABLED: bool = True
    HSTS_MAX_AGE: int = 31536000  # 1 year

    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

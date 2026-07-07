import time
import json
import hashlib
import uuid
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from datetime import datetime
from jose import jwt, JWTError
from typing import Dict, Tuple

from src.core.config import settings
from src.core.database import SessionLocal
from src.core.trusted_proxy import get_resolver
from src.core import security
from src.utils.audit import AuditLogger
from src.models.models import APIKey, BlockedEntity, User
from src.services.user_behavior_analytics import UserBehaviorAnalyticsService
from src.utils.metrics_collector import metrics
from sqlalchemy import and_

logger = logging.getLogger(__name__)

# Very simple in-memory rate limiter
# In production, use Redis backend
class InMemoryRateLimiter:
    def __init__(self):
        self.requests: Dict[str, list] = {}

    def is_rate_limited(self, ip: str, max_requests: int, window: int = 60) -> bool:
        now = time.time()
        if ip not in self.requests:
            self.requests[ip] = []
        
        # Clean up old requests
        self.requests[ip] = [req_time for req_time in self.requests[ip] if now - req_time < window]
        
        if len(self.requests[ip]) >= max_requests:
            return True
            
        self.requests[ip].append(now)
        return False

rate_limiter = InMemoryRateLimiter()

class TrustedProxyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Resolve IP using the trusted proxy resolver
        resolved_ip = get_resolver().get_client_ip(request)
        request.state.client_ip = resolved_ip
        
        start_time = time.time()
        response = await call_next(request)
        
        # Collect basic metrics
        duration = time.time() - start_time
        metrics.increment(f"requests_{request.method}_{response.status_code}")
        metrics.observe("scan_duration_seconds", duration)
        
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)

        client_ip = getattr(request.state, "client_ip", request.client.host if request.client else "unknown")
        
        # Determine limit based on endpoint
        path = request.url.path
        limit = settings.RATE_LIMIT_DEFAULT_RPM
        if "/scan" in path:
            limit = settings.RATE_LIMIT_SCAN_RPM
        elif "/auth" in path or "/login" in path:
            limit = settings.RATE_LIMIT_AUTH_RPM
            
        if rate_limiter.is_rate_limited(client_ip, limit):
            logger.warning(f"Rate limit exceeded for IP {client_ip} on path {path}")
            return JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests"},
                headers={"Retry-After": "60"}
            )
            
        return await call_next(request)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if settings.SECURITY_HEADERS_ENABLED:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = f"max-age={settings.HSTS_MAX_AGE}; includeSubDomains"
            response.headers["Content-Security-Policy"] = "default-src 'self'"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip CSRF for safe methods or API key authenticated requests
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return await call_next(request)
            
        if "x-api-key" in request.headers or "authorization" in request.headers:
             # Assume API client, bypass CSRF (needs proper review in real prod)
             return await call_next(request)

        # For browser session, we expect a CSRF token in header matching cookie
        csrf_cookie = request.cookies.get("csrf_token")
        csrf_header = request.headers.get("x-csrf-token")
        
        # Simplified CSRF check
        if csrf_cookie and csrf_header and csrf_cookie != csrf_header:
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token mismatch"}
            )

        return await call_next(request)

class PreventionMiddleware(BaseHTTPMiddleware):
    """
    Prevention middleware that blocks requests from blocked IPs/entities
    before they reach the application logic
    """
    async def dispatch(self, request: Request, call_next):
        try:
            # Use Trusted Proxy IP
            client_ip = getattr(request.state, "client_ip", get_resolver().get_client_ip(request))
            
            # Use CacheService if Redis enabled, otherwise fallback to DB
            import asyncio
            from src.services.cache_service import CacheService
            # We don't know workspace ID here so we use a wildcard or global lookup
            # Actually, to make it fast, we can check DB directly or loop through workspaces.
            # In an enterprise architecture, blocked IPs might be globally cached.
            # For now, we fallback to DB query directly.
            
            db = SessionLocal()
            now = datetime.utcnow()
            blocked_entity = db.query(BlockedEntity).filter(
                and_(
                    BlockedEntity.entity == client_ip,
                    BlockedEntity.blocked_until > now,
                    BlockedEntity.resolved_status == False
                )
            ).first()
            
            if blocked_entity:
                blocked_entity.blocked_request_count += 1
                db.commit()
                db.close()
                metrics.increment("active_blocks_hit")
                
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": "blocked",
                        "reason": "Your IP address has been blocked due to suspicious activity",
                        "entity": client_ip,
                        "blocked_until": blocked_entity.blocked_until.isoformat(),
                    }
                )
            db.close()
        except Exception as e:
            logger.error(f"Prevention Middleware Error: {e}")
            # If middleware fails, allow request to proceed (fail-open)
        
        return await call_next(request)


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        await self._record_uba_activity(request)

        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return await call_next(request)

        response = await call_next(request)

        # Dispatch async audit log using Celery task if enabled
        try:
            # Simple metadata extraction
            metadata = {
                "path": request.url.path,
                "method": request.method,
                "client_ip": getattr(request.state, "client_ip", "unknown"),
                "status_code": response.status_code
            }
            
            from src.workers.tasks import dispatch_audit_log
            dispatch_audit_log(
                action=f"api_{request.method.lower()}",
                module="gateway",
                status="success" if response.status_code < 400 else "failure",
                metadata=metadata
            )
        except Exception as e:
            logger.error(f"Audit Logging Error: {e}")

        return response

    async def _record_uba_activity(self, request: Request) -> None:
        path = request.url.path
        if path in {"/", "/docs", "/openapi.json"} or path.endswith((".js", ".css", ".png", ".svg", ".ico")):
            return

        db = SessionLocal()
        try:
            user = self._resolve_user_from_bearer(db, request)
            api_key = self._resolve_api_key(db, request)
            workspace_id = user.workspace_id if user else api_key.workspace_id if api_key else None
            if not workspace_id:
                return

            event_type = "api_request"
            if path.startswith(settings.API_V1_STR) and api_key:
                event_type = "api_key_usage"
            elif path.startswith(settings.API_V1_STR):
                event_type = "dashboard_activity"

            UserBehaviorAnalyticsService.record_event(
                db=db,
                workspace_id=workspace_id,
                user_id=user.id if user else None,
                event_type=event_type,
                ip_address=getattr(request.state, "client_ip", None),
                endpoint_accessed=path,
                metadata={"method": request.method},
            )
        except Exception as exc:
            logger.error(f"UBA middleware telemetry failed: {exc}")
        finally:
            db.close()

    def _resolve_user_from_bearer(self, db, request: Request) -> User | None:
        # Check cookie first for browser sessions, then auth header
        token = request.cookies.get("access_token")
        if not token:
            auth_header = request.headers.get("authorization") or ""
            if auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1]
        
        if not token:
            return None
            
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            subject = payload.get("sub")
            return db.query(User).filter(User.id == uuid.UUID(subject)).first() if subject else None
        except (JWTError, ValueError):
            return None

    def _resolve_api_key(self, db, request: Request) -> APIKey | None:
        api_key = request.headers.get("x-api-key")
        if not api_key:
            return None
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return db.query(APIKey).filter(APIKey.key_hash == key_hash, APIKey.is_active == True).first()

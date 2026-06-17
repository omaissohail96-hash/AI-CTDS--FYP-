import time
import json
import hashlib
import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from datetime import datetime
from jose import jwt, JWTError
from src.core.config import settings
from src.core.database import SessionLocal
from src.utils.audit import AuditLogger
from src.models.models import APIKey, BlockedEntity, User
from src.services.user_behavior_analytics import UserBehaviorAnalyticsService
from sqlalchemy import and_

class PreventionMiddleware(BaseHTTPMiddleware):
    """
    Prevention middleware that blocks requests from blocked IPs/entities
    before they reach the application logic
    """
    async def dispatch(self, request: Request, call_next):
        try:
            # Extract client IP from request
            client_ip = self._get_client_ip(request)
            
            # Check if IP is blocked in any workspace
            # (Since middleware doesn't have workspace context, we check all workspaces)
            db = SessionLocal()
            
            now = datetime.utcnow()
            blocked_entity = db.query(BlockedEntity).filter(
                and_(
                    BlockedEntity.entity == client_ip,
                    BlockedEntity.blocked_until > now,
                    BlockedEntity.resolved_status == False
                )
            ).first()
            
            db.close()
            
            if blocked_entity:
                # Increment blocked request counter
                db = SessionLocal()
                blocked_entity_db = db.query(BlockedEntity).filter(
                    BlockedEntity.id == blocked_entity.id
                ).first()
                if blocked_entity_db:
                    blocked_entity_db.blocked_request_count += 1
                    db.commit()
                db.close()
                
                # Return 403 Forbidden
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": "blocked",
                        "reason": "Your IP address has been blocked due to suspicious activity",
                        "entity": client_ip,
                        "blocked_until": blocked_entity.blocked_until.isoformat(),
                    }
                )
        except Exception as e:
            print(f"Prevention Middleware Error: {e}")
            # If middleware fails, allow request to proceed (fail-open)
        
        response = await call_next(request)
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, considering proxy headers"""
        # Check for X-Forwarded-For (cloud/proxy environments)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check for X-Real-IP
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Use direct client connection IP
        if request.client:
            return request.client.host
        
        return "unknown"


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        await self._record_uba_activity(request)

        # We only want to auto-log mutations (POST, PUT, DELETE, PATCH)
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return await call_next(request)

        # Process the request
        response = await call_next(request)

        # Attempt to log the activity asynchronously (Best effort)
        # Note: In a production app, we might use a background task or message queue
        try:
            db = SessionLocal()
            
            # Simple metadata extraction
            metadata = {
                "path": request.url.path,
                "method": request.method,
                "client_ip": request.client.host if request.client else "unknown",
                "status_code": response.status_code
            }

            # We don't have easy access to 'current_user' or 'workspace' here without 
            # re-decoding JWT or extracting from response context.
            # For this Phase, we'll log the "Raw API Activity"
            
            AuditLogger.log(
                db,
                action=f"api_{request.method.lower()}",
                module="gateway",
                status="success" if response.status_code < 400 else "failure",
                metadata=metadata
            )
            db.close()
        except Exception as e:
            print(f"Audit Logging Error: {e}")

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
                ip_address=request.client.host if request.client else None,
                endpoint_accessed=path,
                metadata={"method": request.method},
            )
        except Exception as exc:
            print(f"UBA middleware telemetry failed: {exc}")
        finally:
            db.close()

    def _resolve_user_from_bearer(self, db, request: Request) -> User | None:
        auth_header = request.headers.get("authorization") or ""
        if not auth_header.lower().startswith("bearer "):
            return None
        token = auth_header.split(" ", 1)[1]
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

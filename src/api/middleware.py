import time
import json
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from src.core.database import SessionLocal
from src.utils.audit import AuditLogger

class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
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

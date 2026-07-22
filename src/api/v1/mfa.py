import pyotp
import qrcode
import base64
import json
import uuid
import secrets
from io import BytesIO
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.api import deps
from src.core import security
from src.core.config import settings
from src.core.trusted_proxy import get_client_ip
from src.models.models import User, UserMFA
from src.api.v1.auth import _store_refresh_token, _set_auth_cookies, _record_successful_login
from src.services.user_behavior_analytics import UserBehaviorAnalyticsService

router = APIRouter()

class MFAVerifyRequest(BaseModel):
    code: str

@router.post("/setup")
def setup_mfa(
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Initialize MFA for a user and return the provisioning URI and QR Code base64."""
    user_mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    if user_mfa and user_mfa.enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")

    # Generate new secret
    secret = pyotp.random_base32()
    
    if not user_mfa:
        user_mfa = UserMFA(user_id=current_user.id, secret=secret)
        db.add(user_mfa)
    else:
        user_mfa.secret = secret
        
    db.commit()
    
    # Generate Provisioning URI
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="CyberGuard AI")
    
    # Generate QR Code
    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return {
        "secret": secret,
        "qr_code_base64": qr_base64,
        "provisioning_uri": provisioning_uri
    }

@router.post("/verify")
def verify_mfa_setup(
    req: MFAVerifyRequest,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Verify the code during setup to enable MFA."""
    user_mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    if not user_mfa or user_mfa.enabled:
        raise HTTPException(status_code=400, detail="MFA setup not initiated or already enabled")

    totp = pyotp.TOTP(user_mfa.secret)
    if not totp.verify(req.code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")

    # Enable and generate recovery codes
    user_mfa.enabled = True
    recovery_codes = [secrets.token_hex(4) for _ in range(8)]
    user_mfa.recovery_codes = recovery_codes
    db.commit()

    return {
        "detail": "MFA enabled successfully",
        "recovery_codes": recovery_codes
    }

@router.post("/disable")
def disable_mfa(
    req: MFAVerifyRequest,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Disable MFA."""
    user_mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    if not user_mfa or not user_mfa.enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    totp = pyotp.TOTP(user_mfa.secret)
    if not totp.verify(req.code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")

    user_mfa.enabled = False
    user_mfa.secret = ""
    user_mfa.recovery_codes = []
    db.commit()

    return {"detail": "MFA disabled successfully"}

@router.post("/verify-login")
def verify_mfa_login(
    req: MFAVerifyRequest,
    request: Request,
    response: Response,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Verify MFA code during login and issue final tokens."""
    user_mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    if not user_mfa or not user_mfa.enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled for this user")

    # Verify code (or recovery code)
    valid = False
    totp = pyotp.TOTP(user_mfa.secret)
    if totp.verify(req.code):
        valid = True
    elif req.code in user_mfa.recovery_codes:
        valid = True
        # remove used recovery code
        codes = list(user_mfa.recovery_codes)
        codes.remove(req.code)
        user_mfa.recovery_codes = codes
        db.commit()

    if not valid:
        raise HTTPException(status_code=400, detail="Invalid MFA code")

    # Issue final tokens
    access_token = security.create_access_token(current_user.id)
    refresh_token = security.create_refresh_token(current_user.id, token_version=current_user.refresh_token_version)
    _store_refresh_token(db, current_user, refresh_token, request)
    _set_auth_cookies(response, access_token, refresh_token)

    # Record the completed login (increments login_count, updates last_login_ip/at)
    _record_successful_login(db, current_user, request)

    # Audit + UBA
    from src.utils.audit import AuditLogger
    AuditLogger.log(
        db,
        action="login_mfa_success",
        module="auth",
        workspace_id=current_user.workspace_id,
        user_id=current_user.id,
        metadata={"ip": get_client_ip(request)},
    )
    try:
        UserBehaviorAnalyticsService.record_event(
            db=db,
            workspace_id=current_user.workspace_id,
            user_id=current_user.id,
            event_type="login_success",
            ip_address=get_client_ip(request),
            endpoint_accessed=str(request.url.path),
        )
    except Exception as exc:
        print(f"UBA login telemetry failed: {exc}")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


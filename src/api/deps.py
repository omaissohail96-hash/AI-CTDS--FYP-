from typing import Generator, Optional
import uuid

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from src.core.database import SessionLocal
from src.core import security
from src.core.config import settings
from src.models.models import User, APIKey, Workspace, Role, Permission, RolePermission

# We use auto_error=False so we can manually check cookies before failing over to Bearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token", auto_error=False)


def get_db() -> Generator:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def get_token_from_request(request: Request, bearer_token: str = Depends(oauth2_scheme)) -> str:
    """
    Extract the access token either from the HttpOnly cookie OR the Authorization header.
    Cookie takes precedence for browser sessions.
    """
    # 1. Try cookie first
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token

    # 2. Try bearer token
    if bearer_token:
        return bearer_token

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_request)
) -> User:
    """
    Validate the access token and return the associated User.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[security.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        if user_id is None or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return user


def get_current_workspace(current_user: User = Depends(get_current_user)) -> Workspace:
    """
    Returns the workspace associated with the currently authenticated user.
    """
    if not current_user.workspace_id:
        raise HTTPException(status_code=400, detail="User is not assigned to a workspace")
    # For now we'll just return an object with the ID to avoid a DB hit if we only need the ID
    # In a full implementation, you might want to fetch the actual workspace object
    return type('obj', (object,), {'id': current_user.workspace_id})()


def get_api_key(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[APIKey]:
    """
    Extracts and validates an API key from the X-API-Key header.
    Returns the APIKey object or raises 401 if invalid.
    """
    api_key_header = request.headers.get("X-API-Key")
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key required for this endpoint"
        )

    # In a real system, you'd hash the incoming key and look it up
    # Here we simulate looking up the APIKey object
    import hashlib
    key_hash = hashlib.sha256(api_key_header.encode()).hexdigest()

    # For cache check:
    # key_data = CacheService.get_api_key(key_hash)
    # if key_data: return key_data
    
    api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash, APIKey.is_active == True).first()
    if not api_key:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API Key"
        )
    return api_key


class RequirePermissions:
    def __init__(self, required_permissions: list[str]):
        self.required_permissions = required_permissions

    def __call__(
        self,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """
        Check if the current user has the required permissions based on their role.
        """
        # Get the user's role from the database
        role = db.query(Role).filter(Role.name == current_user.role).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Role not found"
            )

        # Get all permissions for this role
        permissions = db.query(Permission.name).join(
            RolePermission, Permission.id == RolePermission.permission_id
        ).filter(
            RolePermission.role_id == role.id
        ).all()

        user_permissions = {p[0] for p in permissions}

        # Check if the user has all required permissions
        for req_perm in self.required_permissions:
            if req_perm not in user_permissions and "all" not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permission: {req_perm}"
                )
        return current_user

require_permissions = RequirePermissions


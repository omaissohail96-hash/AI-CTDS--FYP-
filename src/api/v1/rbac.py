"""
CyberGuard AI – RBAC Management Endpoints
==========================================

GET  /api/v1/rbac/my-permissions  – Return the current user's role + permissions
GET  /api/v1/rbac/roles           – List all roles & permissions (super_admin only)
PUT  /api/v1/users/{user_id}/role – Change a user's role (workspace_admin+)
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.deps import (
    RequirePermissions,
    RequireRoles,
    get_auth_context,
    get_current_user,
    get_db,
    _load_permissions,
    AuthContext,
)
from src.core.rbac import ROLE_DESCRIPTIONS, ROLE_PERMISSIONS, WorkspaceRole, normalize_workspace_role
from src.models.models import Permission, Role, RolePermission, User, Workspace, WorkspaceUser
from src.utils.audit import AuditLogger

router = APIRouter()

VALID_ROLES = {"super_admin", "workspace_admin", "security_analyst", "viewer"}


# ── Schemas ───────────────────────────────────────────────────────────────────

class MyPermissionsResponse(BaseModel):
    user_id: str
    email: str
    role: str
    permissions: List[str]
    workspace_id: str


class RoleDetail(BaseModel):
    name: str
    description: Optional[str]
    permissions: List[str]


class RoleChangeRequest(BaseModel):
    role: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/my-permissions", response_model=MyPermissionsResponse)
def get_my_permissions(
    ctx: AuthContext = Depends(get_auth_context),
) -> Any:
    """
    Return the calling user's role and full permission set.
    Used by the frontend to gate UI components.
    """
    return MyPermissionsResponse(
        user_id=str(ctx.user.id),
        email=ctx.user.email,
        role=ctx.role,
        permissions=sorted(ctx.permissions),
        workspace_id=str(ctx.workspace.id),
    )


@router.get("/roles", response_model=List[RoleDetail])
def list_roles(
    _: AuthContext = Depends(get_auth_context),
) -> Any:
    """
    List all roles and their associated permissions.
    Requires system:admin permission (super_admin only).
    """
    return [RoleDetail(name=role, description=ROLE_DESCRIPTIONS[role], permissions=sorted(perms))
            for role, perms in ROLE_PERMISSIONS.items()]


@router.put("/users/{user_id}/role", response_model=Dict[str, Any])
def change_user_role(
    user_id: str,
    payload: RoleChangeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    ctx: AuthContext = Depends(get_auth_context),
) -> Any:
    """
    Change the role of a user within the current workspace.

    Rules:
    - workspace_admin can assign: workspace_admin, security_analyst, viewer
    - super_admin can assign any role
    - Users cannot demote themselves
    - Workspace isolation: can only change users in own workspace
    """
    actor_role = ctx.role
    if actor_role not in {WorkspaceRole.OWNER.value, WorkspaceRole.ADMIN.value}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only workspace admins and super admins can change user roles.",
        )

    new_role = normalize_workspace_role(payload.role)
    if payload.role.strip().lower() != new_role or new_role == WorkspaceRole.OWNER.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{new_role}'. Valid roles: {sorted(VALID_ROLES)}.",
        )

    if actor_role == WorkspaceRole.ADMIN.value and new_role == WorkspaceRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Workspace admins cannot grant the super_admin role.",
        )

    # Parse target user UUID
    try:
        target_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID.")

    # Prevent self-demotion
    if target_uuid == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role.",
        )

    # Workspace isolation (non-super-admins can only change users in own workspace)
    target_user = db.query(User).filter(User.id == target_uuid).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    membership = db.query(WorkspaceUser).filter(
        WorkspaceUser.workspace_id == ctx.workspace.id,
        WorkspaceUser.user_id == target_user.id,
    ).first()
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify users outside your workspace.")
    if membership.user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot change your own role.")
    if membership.role == WorkspaceRole.OWNER.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Transfer ownership to change the owner role.")
    if actor_role == WorkspaceRole.ADMIN.value and membership.role == WorkspaceRole.ADMIN.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins cannot modify another admin.")

    old_role = membership.role
    membership.role = new_role
    target_user.role = new_role
    db.commit()

    AuditLogger.log(
        db,
        action="user_role_changed",
        module="rbac",
        status="success",
        workspace_id=ctx.workspace.id,
        user_id=current_user.id,
        metadata={
            "target_user_id": str(target_uuid),
            "target_email": target_user.email,
            "from_role": old_role,
            "to_role": new_role,
        },
    )

    return {
        "user_id": user_id,
        "email": target_user.email,
        "previous_role": old_role,
        "new_role": new_role,
        "message": f"Role updated from '{old_role}' to '{new_role}'.",
    }

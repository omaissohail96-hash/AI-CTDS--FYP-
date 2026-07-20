"""Workspace configuration, membership, and role administration APIs."""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from src.api import deps
from src.api.deps import AuthContext
from src.core.rbac import (
    ROLE_DESCRIPTIONS, ROLE_PERMISSIONS, WorkspaceRole, assignable_roles,
    normalize_workspace_role,
)
from src.models.models import User, Workspace, WorkspaceUser
from src.utils.audit import AuditLogger

router = APIRouter()


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: str = Field(default=WorkspaceRole.VIEWER.value)


class UpdateMemberRoleRequest(BaseModel):
    role: str


class TransferOwnershipRequest(BaseModel):
    member_id: str


class ApproveMemberRequest(BaseModel):
    role: str = Field(default=WorkspaceRole.VIEWER.value)


def _member_payload(member: WorkspaceUser, user: User) -> dict[str, Any]:
    return {
        "id": str(member.id),
        "user_id": str(user.id),
        "name": user.full_name or "",
        "email": user.email,
        "role": member.role,
        "joined_at": member.joined_at.isoformat() if member.joined_at else None,
        "updated_at": member.updated_at.isoformat() if member.updated_at else None,
        "status": member.status if user.is_active else "inactive",
    }


def _get_member(db: Session, workspace_id, member_id: str) -> tuple[WorkspaceUser, User]:
    try:
        identifier = uuid.UUID(member_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid member ID.") from exc

    member = db.query(WorkspaceUser).filter(
        WorkspaceUser.id == identifier,
        WorkspaceUser.workspace_id == workspace_id,
    ).first()
    if not member:
        raise HTTPException(status_code=404, detail="Workspace member not found.")
    user = db.query(User).filter(User.id == member.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Member user not found.")
    return member, user


def _validate_assignment(actor_role: str, requested_role: str, target_role: Optional[str] = None) -> str:
    role = normalize_workspace_role(requested_role)
    actor_role = normalize_workspace_role(actor_role)
    if requested_role.strip().lower() != role:
        raise HTTPException(status_code=400, detail="Invalid workspace role.")
    if role == WorkspaceRole.OWNER.value:
        raise HTTPException(status_code=403, detail="Use the ownership transfer endpoint to assign the owner role.")
    if role not in assignable_roles(actor_role):
        raise HTTPException(status_code=403, detail="You cannot assign that workspace role.")
    if target_role and normalize_workspace_role(target_role) == WorkspaceRole.OWNER.value:
        raise HTTPException(status_code=403, detail="Owner membership can only be changed through ownership transfer.")
    if target_role and actor_role == WorkspaceRole.ADMIN.value and normalize_workspace_role(target_role) == WorkspaceRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Admins cannot modify another admin.")
    return role


@router.get("/info")
def get_workspace_info(
    workspace: Workspace = Depends(deps.get_current_workspace),
    ctx: AuthContext = Depends(deps.get_auth_context),
) -> Any:
    return {
        "id": str(workspace.id), "name": workspace.name, "tier": workspace.tier,
        "monthly_quota": workspace.monthly_quota, "rate_limit_rpm": workspace.rate_limit_rpm,
        "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
        "current_role": ctx.role,
    }


@router.get("/members")
def list_members(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: AuthContext = Depends(deps.require_permissions("workspace:members:read")),
) -> dict[str, Any]:
    rows = db.query(WorkspaceUser, User).join(User, User.id == WorkspaceUser.user_id).filter(
        WorkspaceUser.workspace_id == workspace.id
    ).order_by(WorkspaceUser.joined_at.asc()).all()
    return {"members": [_member_payload(member, user) for member, user in rows]}


@router.post("/invite", status_code=status.HTTP_201_CREATED)
def invite_member(
    payload: InviteMemberRequest,
    request: Request,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    ctx: AuthContext = Depends(deps.require_permissions("workspace:members:manage")),
) -> dict[str, Any]:
    role = _validate_assignment(ctx.role, payload.role)
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found. Ask the user to register before inviting them.")
    if user.workspace_id and user.workspace_id != workspace.id:
        raise HTTPException(status_code=409, detail="User already belongs to another workspace.")
    if db.query(WorkspaceUser).filter(
        WorkspaceUser.workspace_id == workspace.id, WorkspaceUser.user_id == user.id
    ).first():
        raise HTTPException(status_code=409, detail="User is already a workspace member.")

    user.workspace_id = workspace.id
    user.role = role  # Legacy compatibility for existing consumers.
    member = WorkspaceUser(workspace_id=workspace.id, user_id=user.id, role=role, status="active", invited_by=ctx.user.id)
    db.add(member)
    db.commit()
    db.refresh(member)
    AuditLogger.log(db, "workspace_member_invited", "rbac", workspace_id=workspace.id, user_id=ctx.user.id,
                    metadata={"member_id": str(member.id), "target_email": user.email, "role": role, "ip": deps._get_client_ip(request)})
    return _member_payload(member, user)


@router.patch("/member/{member_id}/role")
def update_member_role(
    member_id: str,
    payload: UpdateMemberRoleRequest,
    request: Request,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    ctx: AuthContext = Depends(deps.require_permissions("workspace:members:manage")),
) -> dict[str, Any]:
    member, user = _get_member(db, workspace.id, member_id)
    if member.user_id == ctx.user.id:
        raise HTTPException(status_code=400, detail="You cannot edit your own role.")
    if member.status == "pending":
        raise HTTPException(status_code=400, detail="Pending members must be approved by a workspace administrator.")
    role = _validate_assignment(ctx.role, payload.role, member.role)
    previous_role = member.role
    member.role = role
    user.role = role
    db.commit()
    AuditLogger.log(db, "workspace_member_role_changed", "rbac", workspace_id=workspace.id, user_id=ctx.user.id,
                    metadata={"member_id": member_id, "target_email": user.email, "from_role": previous_role, "to_role": role, "ip": deps._get_client_ip(request)})
    return _member_payload(member, user)


@router.post("/member/{member_id}/approve")
def approve_pending_member(
    member_id: str,
    payload: ApproveMemberRequest,
    request: Request,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    ctx: AuthContext = Depends(deps.require_permissions("workspace:members:manage")),
) -> dict[str, Any]:
    """Approve a pending workspace-registration request and assign its role."""
    if ctx.role not in {WorkspaceRole.OWNER.value, WorkspaceRole.ADMIN.value}:
        raise HTTPException(status_code=403, detail="Only workspace administrators can approve members.")
    member, user = _get_member(db, workspace.id, member_id)
    if member.status != "pending":
        raise HTTPException(status_code=400, detail="This member is not pending approval.")
    role = _validate_assignment(ctx.role, payload.role)
    member.role = role
    member.status = "active"
    user.role = role
    db.commit()
    AuditLogger.log(db, "workspace_member_approved", "rbac", workspace_id=workspace.id, user_id=ctx.user.id,
                    metadata={"member_id": member_id, "target_email": user.email, "role": role, "ip": deps._get_client_ip(request)})
    return _member_payload(member, user)


@router.delete("/member/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    member_id: str,
    request: Request,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    ctx: AuthContext = Depends(deps.require_permissions("workspace:members:manage")),
) -> None:
    member, user = _get_member(db, workspace.id, member_id)
    if member.user_id == ctx.user.id:
        raise HTTPException(status_code=400, detail="You cannot remove yourself from the workspace.")
    if normalize_workspace_role(member.role) == WorkspaceRole.OWNER.value:
        raise HTTPException(status_code=403, detail="Transfer ownership before removing the owner.")
    if normalize_workspace_role(member.role) not in assignable_roles(ctx.role):
        raise HTTPException(status_code=403, detail="You cannot remove this workspace member.")
    db.delete(member)
    db.commit()
    AuditLogger.log(db, "workspace_member_removed", "rbac", workspace_id=workspace.id, user_id=ctx.user.id,
                    metadata={"member_id": member_id, "target_email": user.email, "ip": deps._get_client_ip(request)})


@router.post("/transfer-ownership")
def transfer_ownership(
    payload: TransferOwnershipRequest,
    request: Request,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    ctx: AuthContext = Depends(deps.require_owner()),
) -> dict[str, Any]:
    target, target_user = _get_member(db, workspace.id, payload.member_id)
    if target.user_id == ctx.user.id:
        raise HTTPException(status_code=400, detail="You already own this workspace.")
    current_owner = db.query(WorkspaceUser).filter(
        WorkspaceUser.workspace_id == workspace.id, WorkspaceUser.user_id == ctx.user.id
    ).first()
    if not current_owner:
        raise HTTPException(status_code=403, detail="Owner membership is required.")
    current_owner.role = WorkspaceRole.ADMIN.value
    target.role = WorkspaceRole.OWNER.value
    ctx.user.role = WorkspaceRole.ADMIN.value
    target_user.role = WorkspaceRole.OWNER.value
    db.commit()
    AuditLogger.log(db, "workspace_ownership_transferred", "rbac", workspace_id=workspace.id, user_id=ctx.user.id,
                    metadata={"new_owner_member_id": str(target.id), "new_owner_email": target_user.email, "ip": deps._get_client_ip(request)})
    return {"message": "Workspace ownership transferred.", "new_owner": _member_payload(target, target_user)}


@router.get("/roles")
def list_workspace_roles(_: AuthContext = Depends(deps.get_auth_context)) -> dict[str, Any]:
    return {"roles": [{"name": role, "description": ROLE_DESCRIPTIONS[role]} for role in ROLE_PERMISSIONS]}


@router.get("/permissions")
def list_workspace_permissions(_: AuthContext = Depends(deps.get_auth_context)) -> dict[str, Any]:
    return {"permissions": {role: sorted(permissions) for role, permissions in ROLE_PERMISSIONS.items()}}

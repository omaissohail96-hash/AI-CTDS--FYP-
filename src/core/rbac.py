"""Central workspace RBAC policy for CyberGuard AI."""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet


class WorkspaceRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    OPERATOR = "operator"
    VIEWER = "viewer"


ROLE_DESCRIPTIONS = {
    WorkspaceRole.OWNER.value: "Full workspace control, including ownership and membership management.",
    WorkspaceRole.ADMIN.value: "Workspace administration without ownership, billing, or owner management.",
    WorkspaceRole.ANALYST.value: "Investigation and response access for security analysts.",
    WorkspaceRole.OPERATOR.value: "Operational scanning and alert acknowledgement access.",
    WorkspaceRole.VIEWER.value: "Read-only dashboard, analytics, scan history, and report access.",
}

BASE_READ = {
    "dashboard:read", "scans:read", "alerts:read", "reports:read",
    "analytics:read", "threats:read", "mitre:read",
}

ROLE_PERMISSIONS: dict[str, FrozenSet[str]] = {
    WorkspaceRole.OWNER.value: frozenset({
        *BASE_READ, "scans:create", "alerts:write", "alerts:acknowledge",
        "hunting:read", "uba:read", "explanations:read", "prevention:read",
        "prevention:write", "false_positives:submit", "false_positives:review",
        "review_queue:read", "review_queue:write", "api_keys:read", "api_keys:write",
        "settings:read", "settings:write", "workspace:members:read",
        "workspace:members:manage", "workspace:ownership:transfer",
        "workspace:delete", "workspace:billing:manage", "audit:read", "system:admin",
    }),
    WorkspaceRole.ADMIN.value: frozenset({
        *BASE_READ, "scans:create", "alerts:write", "alerts:acknowledge",
        "hunting:read", "uba:read", "explanations:read", "prevention:read",
        "prevention:write", "false_positives:submit", "false_positives:review",
        "review_queue:read", "review_queue:write", "api_keys:read", "api_keys:write",
        "settings:read", "settings:write", "workspace:members:read",
        "workspace:members:manage", "audit:read",
    }),
    WorkspaceRole.ANALYST.value: frozenset({
        *BASE_READ, "scans:create", "alerts:write", "hunting:read", "uba:read",
        "explanations:read", "prevention:read", "false_positives:submit",
        "review_queue:read", "reports:export", "audit:read",
    }),
    WorkspaceRole.OPERATOR.value: frozenset({
        *BASE_READ, "scans:create", "alerts:acknowledge",
    }),
    WorkspaceRole.VIEWER.value: frozenset(BASE_READ),
}

# Existing installations used these values on ``users.role``. Keep them valid
# while progressively moving authorization to WorkspaceUser.role.
LEGACY_ROLE_MAP = {
    "super_admin": WorkspaceRole.OWNER.value,
    "workspace_admin": WorkspaceRole.ADMIN.value,
    "security_analyst": WorkspaceRole.ANALYST.value,
    "viewer": WorkspaceRole.VIEWER.value,
    "admin": WorkspaceRole.ADMIN.value,
    "developer": WorkspaceRole.OPERATOR.value,
}

ROLE_ASSIGNMENT_RANK = {
    WorkspaceRole.VIEWER.value: 1,
    WorkspaceRole.OPERATOR.value: 2,
    WorkspaceRole.ANALYST.value: 3,
    WorkspaceRole.ADMIN.value: 4,
    WorkspaceRole.OWNER.value: 5,
}


def normalize_workspace_role(role: str | None) -> str:
    normalized = (role or WorkspaceRole.VIEWER.value).strip().lower()
    normalized = LEGACY_ROLE_MAP.get(normalized, normalized)
    return normalized if normalized in ROLE_PERMISSIONS else WorkspaceRole.VIEWER.value


def permissions_for_role(role: str | None) -> set[str]:
    return set(ROLE_PERMISSIONS[normalize_workspace_role(role)])


def assignable_roles(actor_role: str) -> set[str]:
    role = normalize_workspace_role(actor_role)
    if role == WorkspaceRole.OWNER.value:
        return {WorkspaceRole.ADMIN.value, WorkspaceRole.ANALYST.value, WorkspaceRole.OPERATOR.value, WorkspaceRole.VIEWER.value}
    if role == WorkspaceRole.ADMIN.value:
        return {WorkspaceRole.ANALYST.value, WorkspaceRole.OPERATOR.value, WorkspaceRole.VIEWER.value}
    return set()

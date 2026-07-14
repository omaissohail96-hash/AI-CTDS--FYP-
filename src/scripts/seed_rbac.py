"""
CyberGuard AI – RBAC Seed Script
=================================
Seeds the four canonical roles and their permissions into the database.
This script is idempotent – safe to run multiple times.

Roles
-----
  super_admin        – Full platform control (cross-workspace)
  workspace_admin    – Full control within a single workspace
  security_analyst   – Detection, alerting, hunting, investigation
  viewer             – Read-only access to dashboards and reports

Usage
-----
  python -m src.scripts.seed_rbac          # standalone
  OR called automatically at app startup via seed_rbac_if_empty()
"""

from __future__ import annotations

import logging
import uuid
from typing import Dict, List

from sqlalchemy.orm import Session

from src.core.database import SessionLocal
from src.models.models import Permission, Role, RolePermission

logger = logging.getLogger(__name__)

# ── Canonical permission definitions ──────────────────────────────────────────

PERMISSIONS: List[Dict[str, str]] = [
    # Dashboard / overview
    {"name": "dashboard:read",          "description": "View dashboard and overview metrics"},
    # Alerts
    {"name": "alerts:read",             "description": "View alerts and alert statistics"},
    {"name": "alerts:write",            "description": "Resolve, escalate, and manage alerts"},
    # Scans
    {"name": "scans:read",              "description": "View scan history and statistics"},
    {"name": "scans:create",            "description": "Submit new scans via agent or scanners"},
    # Threat Hunting
    {"name": "hunting:read",            "description": "Search and investigate scan history"},
    # User Behavior Analytics
    {"name": "uba:read",                "description": "View user behavior events and anomalies"},
    # Prevention / IPS
    {"name": "prevention:read",         "description": "View blocked entities and IPS stats"},
    {"name": "prevention:write",        "description": "Unblock entities and manage IPS policies"},
    # Reports
    {"name": "reports:read",            "description": "View and download security reports"},
    # False Positive Framework
    {"name": "false_positives:submit",  "description": "Submit false positive reports"},
    {"name": "false_positives:review",  "description": "Approve or reject false positive reports"},
    # Review Queue
    {"name": "review_queue:read",       "description": "View the human review queue"},
    {"name": "review_queue:write",      "description": "Action items in the review queue"},
    # Users
    {"name": "users:read",              "description": "View workspace users and their roles"},
    {"name": "users:write",             "description": "Invite, deactivate, and assign roles to users"},
    # API Feedback / HITL
    {"name": "feedback:read",           "description": "View AI feedback and retraining stats"},
    {"name": "feedback:submit",         "description": "Submit feedback on AI predictions"},
    {"name": "feedback:approve",        "description": "Approve feedback to be used in ML retraining"},
    # API Keys
    {"name": "api_keys:read",           "description": "List and inspect API keys"},
    {"name": "api_keys:write",          "description": "Create, rotate, and revoke API keys"},
    # Workspace settings
    {"name": "workspace:read",          "description": "View workspace configuration"},
    {"name": "workspace:write",         "description": "Modify workspace settings"},
    # Super admin
    {"name": "system:admin",            "description": "Cross-workspace administrative control"},
]


# ── Role → Permission mapping ─────────────────────────────────────────────────

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "super_admin": [p["name"] for p in PERMISSIONS],  # all permissions

    "workspace_admin": [
        "dashboard:read",
        "alerts:read", "alerts:write",
        "scans:read", "scans:create",
        "hunting:read",
        "uba:read",
        "prevention:read", "prevention:write",
        "reports:read",
        "false_positives:submit", "false_positives:review",
        "review_queue:read", "review_queue:write",
        "users:read", "users:write",
        "api_keys:read", "api_keys:write",
        "workspace:read", "workspace:write",
        "feedback:read", "feedback:submit", "feedback:approve",
    ],

    "security_analyst": [
        "dashboard:read",
        "alerts:read", "alerts:write",
        "scans:read", "scans:create",
        "hunting:read",
        "uba:read",
        "prevention:read", "prevention:write",
        "reports:read",
        "false_positives:submit", "false_positives:review",
        "review_queue:read", "review_queue:write",
        "feedback:read", "feedback:submit",
    ],

    "viewer": [
        "dashboard:read",
        "alerts:read",
        "scans:read",
        "prevention:read",
        "reports:read",
        "feedback:read",
    ],
}

ROLE_DESCRIPTIONS: Dict[str, str] = {
    "super_admin":      "Full platform control including cross-workspace operations",
    "workspace_admin":  "Full control within a single workspace",
    "security_analyst": "Detection, alerting, hunting and incident response",
    "viewer":           "Read-only access to dashboards and reports",
}


# ── Core seeder ───────────────────────────────────────────────────────────────

def seed_rbac(db: Session) -> Dict[str, int]:
    """
    Upsert all roles and permissions, then wire role->permission mappings.
    Returns a dict with counts of inserted rows.
    """
    inserted = {"roles": 0, "permissions": 0, "role_permissions": 0}

    # 1. Upsert permissions
    perm_map: Dict[str, Permission] = {}
    for pdef in PERMISSIONS:
        existing = db.query(Permission).filter(Permission.name == pdef["name"]).first()
        if existing:
            perm_map[pdef["name"]] = existing
        else:
            perm = Permission(
                id=uuid.uuid4(),
                name=pdef["name"],
                description=pdef["description"],
            )
            db.add(perm)
            perm_map[pdef["name"]] = perm
            inserted["permissions"] += 1

    db.flush()

    # 2. Upsert roles and wire permissions
    for role_name, perm_names in ROLE_PERMISSIONS.items():
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            role = Role(
                id=uuid.uuid4(),
                name=role_name,
                description=ROLE_DESCRIPTIONS.get(role_name, ""),
            )
            db.add(role)
            inserted["roles"] += 1
        else:
            role.description = ROLE_DESCRIPTIONS.get(role_name, role.description)

        db.flush()

        # 3. Sync role->permission entries (add missing, leave existing)
        existing_rp = {
            str(rp.permission_id)
            for rp in db.query(RolePermission)
            .filter(RolePermission.role_id == role.id)
            .all()
        }

        for pname in perm_names:
            perm = perm_map.get(pname)
            if perm is None:
                logger.warning("Permission %s not found in perm_map - skipping", pname)
                continue
            if str(perm.id) not in existing_rp:
                rp = RolePermission(
                    id=uuid.uuid4(),
                    role_id=role.id,
                    permission_id=perm.id,
                )
                db.add(rp)
                inserted["role_permissions"] += 1

    db.commit()
    logger.info(
        "RBAC seed complete: +%d roles, +%d permissions, +%d role_permissions",
        inserted["roles"],
        inserted["permissions"],
        inserted["role_permissions"],
    )
    return inserted


def seed_rbac_if_empty(db: Session) -> bool:
    """
    Seed only if the canonical roles are missing.
    Returns True if seeding was performed.
    """
    existing_names = {r.name for r in db.query(Role).all()}
    expected_names = set(ROLE_PERMISSIONS.keys())
    if not expected_names.issubset(existing_names):
        logger.info("RBAC roles missing - seeding now ...")
        seed_rbac(db)
        return True
    logger.debug("RBAC already seeded (%d roles present) - skipping", len(existing_names))
    return False


def get_permissions_for_role(db: Session, role_name: str) -> set:
    """Return the set of permission names for a given role name."""
    role = db.query(Role).filter(Role.name == role_name).first()
    if not role:
        return set()
    perms = (
        db.query(Permission.name)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .filter(RolePermission.role_id == role.id)
        .all()
    )
    return {p[0] for p in perms}


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(levelname)s %(name)s - %(message)s")
    _db = SessionLocal()
    try:
        result = seed_rbac(_db)
        print(f"Done: {result}")
    finally:
        _db.close()

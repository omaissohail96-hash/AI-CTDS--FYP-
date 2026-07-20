"""
tests/test_rbac.py
==================
Integration tests for CyberGuard AI Role-Based Access Control (RBAC).

Strategy:
  - Use an in-memory SQLite DB for test isolation.
  - Bypass the login endpoint by minting JWTs directly via create_access_token()
    (avoids bcrypt hashing in test fixture setup).
  - Verify that every RBAC-protected endpoint enforces permissions correctly.

Covers:
  - Super Admin: full access
  - Workspace Admin: full access
  - Security Analyst: read + scan access, no settings:write
  - Viewer: read-only, no settings:write
  - API Key: permission-scoped access (scans:read/create only)
  - Unauthenticated: 401 on all protected routes
"""

import uuid
import pytest
from unittest.mock import patch, MagicMock, AsyncMock



from src.models.models import Base, User, Workspace, Role, Permission, RolePermission, APIKey
from src.main import app
from src.core import security
from src.scripts.seed_rbac import seed_rbac
from src.api.deps import _hash_api_key
from tests.conftest import TestingSessionLocal

# ── Shared test state ────────────────────────────────────────────────────────
_state: dict = {}


@pytest.fixture(autouse=True)
def setup_teardown(db):
    """Recreate a fresh DB with one workspace + one user per role before every test."""
    seed_rbac(db)

    ws = Workspace(id=uuid.uuid4(), name="RBAC Test Workspace")
    db.add(ws)
    db.commit()
    db.refresh(ws)

    for role in ["super_admin", "workspace_admin", "security_analyst", "viewer"]:
        u = User(
            id=uuid.uuid4(),
            email=f"{role}@test.com",
            hashed_password=security.get_password_hash("testpassword"),
            role=role,
            workspace_id=ws.id,
            is_active=True,
            refresh_token_version=0,
        )
        db.add(u)

    db.commit()

    # Create an API key with scans:read only — no settings:write
    raw_key = "cg_live_testapikey1234567890abcdef123456"
    key_hash = _hash_api_key(raw_key)
    api_key = APIKey(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        label="Test API Key",
        key_hash=key_hash,
        is_active=True,
    )
    db.add(api_key)
    db.commit()

    _state["ws_id"] = ws.id
    _state["raw_key"] = raw_key
    _state["db"] = db

    yield

    db.close()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_token(role: str) -> str:
    """Mint a JWT directly for the given role user (no login endpoint needed)."""
    db = TestingSessionLocal()
    user = db.query(User).filter(User.email == f"{role}@test.com").first()
    db.close()
    assert user is not None, f"User for role '{role}' not found"
    return security.create_access_token(str(user.id))


def _auth(role: str) -> dict:
    return {"Authorization": f"Bearer {_get_token(role)}"}


# ── Tests: RBAC on reports endpoint ─────────────────────────────────────────

def test_unauthenticated_is_401(client, ):
    """Requests without any credentials must be rejected."""
    res = client.get("/api/v1/reports/security-report")
    assert res.status_code == 401


def test_super_admin_can_access_reports(client, ):
    """Super Admin has scans:read → can download reports."""
    res = client.get("/api/v1/reports/security-report", headers=_auth("super_admin"))
    # 200 (PDF) or 500 (PDF generation failure) are both valid — 401/403 are not
    assert res.status_code not in (401, 403), f"Unexpected: {res.status_code} {res.text}"


def test_workspace_admin_can_access_reports(client, ):
    res = client.get("/api/v1/reports/security-report", headers=_auth("workspace_admin"))
    assert res.status_code not in (401, 403), f"Unexpected: {res.status_code} {res.text}"


def test_analyst_can_access_reports(client, ):
    res = client.get("/api/v1/reports/security-report", headers=_auth("security_analyst"))
    assert res.status_code not in (401, 403), f"Unexpected: {res.status_code} {res.text}"


def test_viewer_can_access_reports(client, ):
    """Viewer has scans:read → should be allowed."""
    res = client.get("/api/v1/reports/security-report", headers=_auth("viewer"))
    assert res.status_code not in (401, 403), f"Unexpected: {res.status_code} {res.text}"


# ── Tests: RBAC on monitoring endpoint ──────────────────────────────────────

def test_unauthenticated_monitoring_is_401(client, ):
    res = client.get("/api/v1/monitoring")
    assert res.status_code == 401


def test_super_admin_can_access_monitoring(client, ):
    res = client.get("/api/v1/monitoring", headers=_auth("super_admin"))
    assert res.status_code not in (401, 403)


def test_viewer_can_access_monitoring(client, ):
    """Viewers have alerts:read → monitoring allowed."""
    res = client.get("/api/v1/monitoring", headers=_auth("viewer"))
    assert res.status_code not in (401, 403)


# ── Tests: RBAC on API key management endpoint ───────────────────────────────

def test_viewer_cannot_list_api_keys(client, ):
    """Viewers lack settings:write → must receive 403."""
    res = client.get("/api-keys/", headers=_auth("viewer"))
    assert res.status_code == 403


def test_analyst_cannot_list_api_keys(client, ):
    """Analysts lack settings:write → must receive 403."""
    res = client.get("/api-keys/", headers=_auth("security_analyst"))
    assert res.status_code == 403


def test_admin_can_list_api_keys(client, ):
    """Workspace Admin has settings:write → allowed."""
    res = client.get("/api-keys/", headers=_auth("workspace_admin"))
    assert res.status_code not in (401, 403), f"Unexpected: {res.status_code} {res.text}"


def test_super_admin_can_list_api_keys(client, ):
    res = client.get("/api-keys/", headers=_auth("super_admin"))
    assert res.status_code not in (401, 403), f"Unexpected: {res.status_code} {res.text}"


def test_analyst_cannot_create_api_key(client, ):
    """POST /api-keys/create requires settings:write → analyst must get 403."""
    res = client.post(
        "/api-keys/create",
        json={"label": "hacker-key"},
        headers=_auth("security_analyst")
    )
    assert res.status_code == 403


# ── Tests: API Key authentication ────────────────────────────────────────────

def test_api_key_bearer_auth_on_reports(client, ):
    """API keys with scans:read should be able to access the reports endpoint."""
    raw_key = _state["raw_key"]
    headers = {"Authorization": f"Bearer {raw_key}"}
    res = client.get("/api/v1/reports/security-report", headers=headers)
    # 200 or 500 (PDF gen) are both fine, 401/403 are not
    assert res.status_code not in (401, 403), f"Unexpected: {res.status_code} {res.text}"


def test_api_key_cannot_access_api_key_management(client, ):
    """API keys don't have settings:write → must be rejected from key management."""
    raw_key = _state["raw_key"]
    headers = {"Authorization": f"Bearer {raw_key}"}
    res = client.get("/api-keys/", headers=headers)
    assert res.status_code == 403


def test_invalid_api_key_is_401(client, ):
    """Garbage API key must return 401."""
    headers = {"Authorization": "Bearer cg_live_invalidkeyxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
    res = client.get("/api/v1/reports/security-report", headers=headers)
    assert res.status_code == 401


def test_missing_auth_is_401(client, ):
    """Completely absent credentials must return 401."""
    res = client.get("/api/v1/reports/security-report")
    assert res.status_code == 401

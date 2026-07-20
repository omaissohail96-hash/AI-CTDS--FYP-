import uuid

from src.core import security
from src.models.models import User, Workspace, WorkspaceUser


def _member(db, workspace, email, role):
    user = User(
        id=uuid.uuid4(), workspace_id=workspace.id, email=email,
        hashed_password="not-used", full_name=email.split("@")[0], role=role, is_active=True,
    )
    db.add(user)
    db.flush()
    membership = WorkspaceUser(workspace_id=workspace.id, user_id=user.id, role=role)
    db.add(membership)
    db.commit()
    return user, membership


def _headers(user):
    return {"Authorization": f"Bearer {security.create_access_token(str(user.id))}"}


def _workspace(db):
    workspace = Workspace(id=uuid.uuid4(), name="RBAC Workspace")
    db.add(workspace)
    db.commit()
    return workspace


def test_owner_can_invite_and_list_members(client, db):
    workspace = _workspace(db)
    owner, _ = _member(db, workspace, "owner@example.com", "owner")
    invitee = User(id=uuid.uuid4(), email="invitee@example.com", hashed_password="not-used", is_active=True)
    db.add(invitee)
    db.commit()

    response = client.post("/api/v1/workspace/invite", json={"email": invitee.email, "role": "analyst"}, headers=_headers(owner))
    assert response.status_code == 201, response.text
    assert response.json()["role"] == "analyst"

    listed = client.get("/api/v1/workspace/members", headers=_headers(owner))
    assert listed.status_code == 200
    assert {member["email"] for member in listed.json()["members"]} == {owner.email, invitee.email}


def test_admin_cannot_assign_or_remove_admin(client, db):
    workspace = _workspace(db)
    admin, _ = _member(db, workspace, "admin@example.com", "admin")
    peer, peer_membership = _member(db, workspace, "peer@example.com", "admin")

    role_change = client.patch(
        f"/api/v1/workspace/member/{peer_membership.id}/role",
        json={"role": "viewer"}, headers=_headers(admin),
    )
    assert role_change.status_code == 403

    removal = client.delete(f"/api/v1/workspace/member/{peer_membership.id}", headers=_headers(admin))
    assert removal.status_code == 403


def test_self_role_change_and_owner_removal_are_rejected(client, db):
    workspace = _workspace(db)
    owner, owner_membership = _member(db, workspace, "owner@example.com", "owner")
    admin, admin_membership = _member(db, workspace, "admin@example.com", "admin")

    own_change = client.patch(
        f"/api/v1/workspace/member/{owner_membership.id}/role",
        json={"role": "admin"}, headers=_headers(owner),
    )
    assert own_change.status_code == 400

    remove_owner = client.delete(f"/api/v1/workspace/member/{owner_membership.id}", headers=_headers(admin))
    assert remove_owner.status_code == 403


def test_owner_can_transfer_ownership(client, db):
    workspace = _workspace(db)
    owner, owner_membership = _member(db, workspace, "owner@example.com", "owner")
    admin, admin_membership = _member(db, workspace, "admin@example.com", "admin")

    response = client.post(
        "/api/v1/workspace/transfer-ownership",
        json={"member_id": str(admin_membership.id)}, headers=_headers(owner),
    )
    assert response.status_code == 200, response.text

    db.refresh(owner_membership)
    db.refresh(admin_membership)
    assert owner_membership.role == "admin"
    assert admin_membership.role == "owner"


def test_registration_creates_owner_only_for_new_workspace(client, db):
    created = client.post("/api/v1/register", json={
        "email": "creator@example.com", "password": "StrongPass1!",
        "full_name": "Creator", "workspace_name": "Created Workspace",
    })
    assert created.status_code == 200, created.text
    creator = db.query(User).filter(User.email == "creator@example.com").first()
    creator_membership = db.query(WorkspaceUser).filter(WorkspaceUser.user_id == creator.id).first()
    assert creator_membership.role == "owner"
    assert creator_membership.status == "active"

    joined = client.post("/api/v1/register", json={
        "email": "joiner@example.com", "password": "StrongPass1!",
        "full_name": "Joiner", "workspace_id": str(creator.workspace_id),
    })
    assert joined.status_code == 200, joined.text
    joiner = db.query(User).filter(User.email == "joiner@example.com").first()
    joiner_membership = db.query(WorkspaceUser).filter(WorkspaceUser.user_id == joiner.id).first()
    assert joiner_membership.role == "viewer"
    assert joiner_membership.status == "pending"

    denied = client.get("/api/v1/rbac/my-permissions", headers=_headers(joiner))
    assert denied.status_code == 403


def test_admin_must_explicitly_approve_pending_registration(client, db):
    workspace = _workspace(db)
    admin, _ = _member(db, workspace, "admin@example.com", "admin")
    pending_user, pending_membership = _member(db, workspace, "pending@example.com", "viewer")
    pending_membership.status = "pending"
    db.commit()

    role_edit = client.patch(
        f"/api/v1/workspace/member/{pending_membership.id}/role",
        json={"role": "analyst"}, headers=_headers(admin),
    )
    assert role_edit.status_code == 400

    approval = client.post(
        f"/api/v1/workspace/member/{pending_membership.id}/approve",
        json={"role": "analyst"}, headers=_headers(admin),
    )
    assert approval.status_code == 200, approval.text
    assert approval.json()["status"] == "active"
    assert approval.json()["role"] == "analyst"

    db.refresh(pending_user)
    assert pending_user.role == "analyst"

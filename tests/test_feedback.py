import csv
import pytest
import uuid
from fastapi.testclient import TestClient
from src.models.models import Base, ScanHistory, AIFeedback, User, Workspace
from src.scripts.seed_rbac import seed_rbac
from src.core import security

@pytest.fixture(autouse=True)
def setup_scan(db):
    seed_rbac(db)

    ws = Workspace(id=uuid.uuid4(), name="Feedback Test WS")
    db.add(ws)
    db.commit()

    u_sa = User(id=uuid.uuid4(), email="sa@test.com", role="super_admin", workspace_id=ws.id, is_active=True, hashed_password="")
    u_viewer = User(id=uuid.uuid4(), email="v@test.com", role="viewer", workspace_id=ws.id, is_active=True, hashed_password="")
    db.add(u_sa)
    db.add(u_viewer)
    db.commit()

    scan = ScanHistory(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        user_id=u_sa.id,
        input_type="web",
        entity="SELECT * FROM users",
        verdict="malicious",
        ml_confidence=98.5,
        risk_score=90
    )
    db.add(scan)
    db.commit()

    token_sa = security.create_access_token(str(u_sa.id))
    headers_sa = {"Authorization": f"Bearer {token_sa}"}

    token_viewer = security.create_access_token(str(u_viewer.id))
    headers_viewer = {"Authorization": f"Bearer {token_viewer}"}

    scan_id = scan.id
    ws_id = ws.id

    return scan_id, headers_sa, headers_viewer, ws_id

def test_submit_feedback(client: TestClient, setup_scan):
    scan_id, headers_sa, _, ws_id = setup_scan
    
    payload = {
        "scan_id": str(scan_id),
        "feedback_type": "false_positive",
        "comments": "This is just a test payload"
    }
    
    res = client.post("/api/v1/feedback", json=payload, headers=headers_sa)
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == str(scan_id)
    assert data["feedback_type"] == "false_positive"
    assert data["actual_label"] == "safe"
    assert data["review_status"] == "pending"

def test_viewer_cannot_submit_feedback(client: TestClient, setup_scan):
    scan_id, _, headers_viewer, _ = setup_scan
    
    payload = {
        "scan_id": str(scan_id),
        "feedback_type": "false_positive"
    }
    
    res = client.post("/api/v1/feedback", json=payload, headers=headers_viewer)
    assert res.status_code == 403

def test_approve_feedback(client: TestClient, setup_scan):
    scan_id, headers_sa, _, _ = setup_scan
    
    # Super admin creates feedback
    payload = {
        "scan_id": str(scan_id),
        "feedback_type": "correct"
    }
    res = client.post("/api/v1/feedback", json=payload, headers=headers_sa)
    feedback_id = res.json()["id"]
    
    # Approve it
    res = client.put(f"/api/v1/feedback/{feedback_id}/approve", headers=headers_sa)
    assert res.status_code == 200
    assert res.json()["review_status"] == "approved"

def test_get_feedback_stats(client: TestClient, setup_scan):
    scan_id, headers_sa, _, _ = setup_scan
    
    # Submit one
    client.post("/api/v1/feedback", json={
        "scan_id": str(scan_id),
        "feedback_type": "correct"
    }, headers=headers_sa)
    
    res = client.get("/api/v1/feedback/stats", headers=headers_sa)
    assert res.status_code == 200
    stats = res.json()
    assert stats["total"] == 1
    assert stats["pending"] == 1
    assert stats["correct"] == 1
    assert stats["false_positives"] == 0

def test_reject_feedback(client: TestClient, setup_scan):
    scan_id, headers_sa, _, _ = setup_scan
    created = client.post("/api/v1/feedback", json={"scan_id": str(scan_id), "feedback_type": "false_negative"}, headers=headers_sa)
    res = client.put(f"/api/v1/feedback/{created.json()['id']}/reject", headers=headers_sa)
    assert res.status_code == 200
    assert res.json()["review_status"] == "rejected"

def test_approval_exports_only_approved_feedback(client: TestClient, setup_scan, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    scan_id, headers_sa, _, _ = setup_scan
    created = client.post("/api/v1/feedback", json={"scan_id": str(scan_id), "feedback_type": "correct"}, headers=headers_sa)
    assert not (tmp_path / "datasets" / "feedback_dataset.csv").exists()
    approved = client.put(f"/api/v1/feedback/{created.json()['id']}/approve", headers=headers_sa)
    assert approved.status_code == 200
    with (tmp_path / "datasets" / "feedback_dataset.csv").open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    assert len(rows) == 1
    assert rows[0]["correct_label"] == "malicious"

def test_workspace_isolation_hides_other_feedback(client: TestClient, setup_scan, db):
    _, headers_sa, _, _ = setup_scan
    other_workspace = Workspace(id=uuid.uuid4(), name="Other workspace")
    other_user = User(id=uuid.uuid4(), email="other@test.com", role="super_admin", workspace_id=other_workspace.id, is_active=True, hashed_password="")
    other_scan = ScanHistory(id=uuid.uuid4(), workspace_id=other_workspace.id, user_id=other_user.id, input_type="url", entity="https://other.example", verdict="safe", ml_confidence=10, risk_score=5)
    other_user_id, other_scan_id = other_user.id, other_scan.id
    db.add_all([other_workspace, other_user, other_scan]); db.commit()
    other_token = security.create_access_token(str(other_user_id))
    other_headers = {"Authorization": f"Bearer {other_token}"}
    assert client.post("/api/v1/feedback", json={"scan_id": str(other_scan_id), "feedback_type": "correct"}, headers=other_headers).status_code == 200
    visible = client.get("/api/v1/feedback", headers=headers_sa)
    assert visible.status_code == 200
    assert visible.json() == []

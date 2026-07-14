import pytest
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.main import app
from src.models.models import Base, ScanHistory, AIFeedback, User, Workspace
from src.api.deps import get_db
from src.scripts.seed_rbac import seed_rbac
from src.core import security

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_feedback.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)

@pytest.fixture(autouse=True)
def setup_scan():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
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
    db.close()

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

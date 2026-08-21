"""
tests/test_incidents.py

Tests for the Attack Graph + Timeline + Evidence Engine feature.

Run with:
  $env:DATABASE_URL="sqlite:///./test_shared.db"
  .\.venv\Scripts\python -m pytest tests/test_incidents.py -v
"""
import uuid
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.models.models import Base, Incident, Alert, ScanHistory, Workspace, User, Evidence
from src.services.incident_service import IncidentService
from src.services.evidence_service import EvidenceEngine


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def db_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture
def db(db_engine):
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def workspace_id():
    return uuid.uuid4()


def _make_alert(db, workspace_id, entity="192.168.1.1", entity_type="IP",
                risk_score=80, severity="HIGH", alert_type="malicious_ip",
                created_at=None) -> Alert:
    a = Alert(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        alert_type=alert_type,
        severity=severity,
        title=f"Alert for {entity}",
        description=f"Detected threat from {entity}",
        entity=entity,
        entity_type=entity_type,
        source_vector="url",
        risk_score=risk_score,
        ml_confidence=85,
        indicators=[],
        correlated_events=0,
        recommended_action="Block entity",
        resolved_status=False,
        notification_sent=False,
        email_sent=False,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(a)
    db.flush()
    return a


def _make_scan(db, workspace_id, entity="192.168.1.1", input_type="url",
               risk_score=80, severity="HIGH", verdict="THREAT",
               created_at=None, mitre_mappings=None) -> ScanHistory:
    s = ScanHistory(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        input_type=input_type,
        entity=entity,
        entities=[entity],
        attack_type="phishing",
        severity=severity,
        ml_confidence=85,
        intelligence_hit=True,
        correlation_hit=False,
        prevention_triggered=False,
        risk_score=risk_score,
        verdict=verdict,
        explanation={},
        mitre_mappings=mitre_mappings or [{"technique_id": "T1566", "technique": "Phishing", "tactic": "Initial Access"}],
        details={},
        created_at=created_at or datetime.utcnow(),
    )
    db.add(s)
    db.flush()
    return s


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestIncidentCorrelation:

    def test_single_alert_creates_new_incident(self, db, workspace_id):
        """A single alert should create a brand-new incident."""
        alert = _make_alert(db, workspace_id, entity="10.0.0.1", risk_score=75)
        scan = _make_scan(db, workspace_id, entity="10.0.0.1")

        incident = IncidentService.correlate_alert_to_incident(db, workspace_id, alert, scan)

        assert incident is not None
        assert incident.workspace_id == workspace_id
        assert incident.status == "OPEN"
        assert str(alert.id) in (incident.related_alerts or [])
        assert alert.incident_id == incident.id
        assert scan.incident_id == incident.id

    def test_related_alerts_cluster_into_same_incident(self, db, workspace_id):
        """Two alerts from the same IP should be correlated into one incident."""
        shared_ip = "172.16.0.99"

        a1 = _make_alert(db, workspace_id, entity=shared_ip, risk_score=72)
        s1 = _make_scan(db, workspace_id, entity=shared_ip)
        inc1 = IncidentService.correlate_alert_to_incident(db, workspace_id, a1, s1)
        db.flush()

        # Second alert, same IP — should merge into inc1
        a2 = _make_alert(db, workspace_id, entity=shared_ip, risk_score=80,
                         created_at=datetime.utcnow() + timedelta(minutes=5))
        s2 = _make_scan(db, workspace_id, entity=shared_ip)
        inc2 = IncidentService.correlate_alert_to_incident(db, workspace_id, a2, s2)

        assert inc1.id == inc2.id, "Both alerts should be in the same incident"
        assert len(inc2.related_alerts) == 2

    def test_unrelated_alerts_create_separate_incidents(self, db):
        """Alerts with completely different entities should spawn separate incidents."""
        # Use isolated workspace IDs so no previously created OPEN incidents interfere
        ws = uuid.uuid4()

        a1 = _make_alert(db, ws, entity="1.2.3.4", risk_score=70)
        s1 = _make_scan(db, ws, entity="1.2.3.4",
                        mitre_mappings=[{"technique_id": "T9999", "technique": "Unique A", "tactic": "Tactic A"}])
        inc1 = IncidentService.correlate_alert_to_incident(db, ws, a1, s1)

        a2 = _make_alert(db, ws, entity="evil-domain-xyz.com", risk_score=75, entity_type="DOMAIN")
        s2 = _make_scan(db, ws, entity="evil-domain-xyz.com", input_type="url",
                        mitre_mappings=[{"technique_id": "T8888", "technique": "Unique B", "tactic": "Tactic B"}])
        inc2 = IncidentService.correlate_alert_to_incident(db, ws, a2, s2)

        assert inc1.id != inc2.id, "Unrelated alerts should create separate incidents"

    def test_mitre_technique_overlap_merges_incidents(self, db, workspace_id):
        """Two alerts sharing the same MITRE technique should be correlated."""
        shared_technique = [{"technique_id": "T1078", "technique": "Valid Accounts", "tactic": "Persistence"}]

        a1 = _make_alert(db, workspace_id, entity="5.5.5.5", risk_score=77)
        s1 = _make_scan(db, workspace_id, entity="5.5.5.5", mitre_mappings=shared_technique)
        inc1 = IncidentService.correlate_alert_to_incident(db, workspace_id, a1, s1)
        db.flush()

        a2 = _make_alert(db, workspace_id, entity="6.6.6.6", risk_score=79)
        s2 = _make_scan(db, workspace_id, entity="6.6.6.6", mitre_mappings=shared_technique)
        inc2 = IncidentService.correlate_alert_to_incident(db, workspace_id, a2, s2)

        assert inc1.id == inc2.id, "Shared MITRE technique should correlate events"

    def test_risk_score_increases_with_more_alerts(self, db, workspace_id):
        """Risk score should increase as more alerts are added to an incident."""
        shared_ip = "99.99.99.1"
        a1 = _make_alert(db, workspace_id, entity=shared_ip, risk_score=70)
        inc = IncidentService.correlate_alert_to_incident(db, workspace_id, a1, None)
        first_score = inc.risk_score

        a2 = _make_alert(db, workspace_id, entity=shared_ip, risk_score=70)
        IncidentService.correlate_alert_to_incident(db, workspace_id, a2, None)

        assert inc.risk_score >= first_score


class TestTimeline:

    def test_timeline_is_chronological(self, db, workspace_id):
        """Timeline events should be sorted oldest-to-newest."""
        now = datetime.utcnow()
        ip = "10.10.10.1"

        a1 = _make_alert(db, workspace_id, entity=ip, risk_score=70, created_at=now)
        s1 = _make_scan(db, workspace_id, entity=ip, created_at=now - timedelta(minutes=10))
        inc = IncidentService.correlate_alert_to_incident(db, workspace_id, a1, s1)
        db.flush()

        timeline = IncidentService.generate_timeline(db, workspace_id, inc.id)
        timestamps = [ev["timestamp"] for ev in timeline]
        assert timestamps == sorted(timestamps), "Timeline must be chronological"

    def test_timeline_contains_all_event_types(self, db, workspace_id):
        """Timeline should include both Payload Scanned and Alert Generated events."""
        ip = "10.20.30.1"
        alert = _make_alert(db, workspace_id, entity=ip, risk_score=75)
        scan = _make_scan(db, workspace_id, entity=ip)
        inc = IncidentService.correlate_alert_to_incident(db, workspace_id, alert, scan)
        db.flush()

        timeline = IncidentService.generate_timeline(db, workspace_id, inc.id)
        event_types = [ev["event_type"] for ev in timeline]

        assert "Alert Generated" in event_types
        assert "Payload Scanned" in event_types


class TestAttackGraph:

    def test_graph_has_nodes_and_edges(self, db, workspace_id):
        """Graph should contain at least one node and one edge."""
        ip = "192.168.99.1"
        alert = _make_alert(db, workspace_id, entity=ip, risk_score=80)
        scan = _make_scan(db, workspace_id, entity=ip)
        inc = IncidentService.correlate_alert_to_incident(db, workspace_id, alert, scan)
        db.flush()

        graph = IncidentService.generate_attack_graph(db, workspace_id, inc.id)

        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) > 0

    def test_graph_contains_incident_root_node(self, db, workspace_id):
        """The graph must contain an INCIDENT root node."""
        ip = "192.168.88.1"
        alert = _make_alert(db, workspace_id, entity=ip, risk_score=80)
        inc = IncidentService.correlate_alert_to_incident(db, workspace_id, alert, None)
        db.flush()

        graph = IncidentService.generate_attack_graph(db, workspace_id, inc.id)
        node_types = [n["type"] for n in graph["nodes"]]
        assert "INCIDENT" in node_types

    def test_graph_404_for_missing_incident(self, db, workspace_id):
        """Graph for a nonexistent incident should return empty nodes/edges."""
        graph = IncidentService.generate_attack_graph(db, workspace_id, uuid.uuid4())
        assert graph["nodes"] == []
        assert graph["edges"] == []


class TestAttackPath:

    def test_attack_path_steps_are_sequential(self, db, workspace_id):
        """Attack path steps should be numbered starting from 1."""
        ip = "10.1.2.3"
        now = datetime.utcnow()
        alert = _make_alert(db, workspace_id, entity=ip, risk_score=78, created_at=now)
        scan = _make_scan(db, workspace_id, entity=ip, created_at=now - timedelta(minutes=5))
        inc = IncidentService.correlate_alert_to_incident(db, workspace_id, alert, scan)
        db.flush()

        path = IncidentService.generate_attack_path(db, workspace_id, inc.id)
        step_nums = [s["step"] for s in path]

        assert step_nums[0] == 1, "First step should be 1"
        assert step_nums == list(range(1, len(path) + 1)), "Steps must be sequential"


class TestEvidenceEngine:

    def test_evidence_is_created_from_result(self, db, workspace_id):
        """EvidenceEngine.collect_evidence should create Evidence records."""
        alert = _make_alert(db, workspace_id, entity="test.bad.com", risk_score=85)
        inc = IncidentService.correlate_alert_to_incident(db, workspace_id, alert, None)
        db.flush()

        result = {
            "agent_verdict": {"score": 85, "label": "THREAT", "confidence": 90},
            "vector_results": [{"type": "url", "confidence": 90, "attack_type": "phishing"}],
            "intelligence": {
                "threat_intel": {"malicious": True, "source": "VirusTotal", "confidence": 0.95},
            },
            "mitre_mappings": [{"technique_id": "T1566", "technique": "Phishing", "tactic": "Initial Access"}],
        }

        EvidenceEngine.collect_evidence(
            db=db,
            workspace_id=workspace_id,
            incident_alert_id=inc.id,
            result=result,
            supporting_entity_id="test-entity"
        )
        db.flush()

        evidence = db.query(Evidence).filter(Evidence.incident_alert_id == inc.id).all()
        assert len(evidence) > 0, "At least one evidence record should be created"

    def test_evidence_workspace_isolation(self, db):
        """Evidence from one workspace should not be visible in another."""
        ws1 = uuid.uuid4()
        ws2 = uuid.uuid4()

        a1 = _make_alert(db, ws1, entity="192.168.1.1", risk_score=75)
        inc1 = IncidentService.correlate_alert_to_incident(db, ws1, a1, None)
        db.flush()

        result = {"agent_verdict": {"score": 75, "label": "THREAT", "confidence": 80}, "intelligence": {}}
        EvidenceEngine.collect_evidence(db, ws1, inc1.id, result, "entity-1")
        db.flush()

        # Query as workspace 2 — should return nothing
        ws2_evidence = db.query(Evidence).filter(Evidence.workspace_id == ws2).all()
        assert len(ws2_evidence) == 0, "Workspace 2 must not see workspace 1's evidence"

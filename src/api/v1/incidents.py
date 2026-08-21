"""
Incident Stories API
====================
Exposes Attack Graph, Timeline, Evidence, Attack Path, and MITRE mappings
for correlated security incidents.

All endpoints require JWT authentication and are scoped to the current workspace.

Routes:
  GET  /incidents                          → list all incidents (paginated)
  GET  /incidents/{id}                     → incident summary
  GET  /incidents/{id}/graph               → attack graph (nodes + edges)
  GET  /incidents/{id}/timeline            → chronological event timeline
  GET  /incidents/{id}/evidence            → collected evidence records
  GET  /incidents/{id}/attack-path         → sequential attack path steps
  GET  /incidents/{id}/mitre              → MITRE ATT&CK technique breakdown
  PUT  /incidents/{id}/status             → update incident status
"""
from typing import Optional, List
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from sqlalchemy import desc

from src.api import deps
from src.api.deps import RequirePermissions
from src.models.models import Workspace, User, Incident, Evidence, Alert
from src.services.incident_service import IncidentService

router = APIRouter()


# ── Response Schemas ──────────────────────────────────────────────────────────

class IncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    severity: str
    risk_score: int
    confidence: int
    first_seen: datetime
    last_seen: datetime
    status: str
    affected_users: Optional[list] = []
    affected_ips: Optional[list] = []
    affected_urls_domains: Optional[list] = []
    affected_endpoints: Optional[list] = []
    related_alerts: Optional[list] = []
    mitre_techniques: Optional[list] = []
    correlation_reasons: Optional[list] = []
    created_at: datetime
    updated_at: datetime


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_type: str
    source: str
    description: str
    value_indicator: Optional[str] = None
    confidence: int
    importance: str
    timestamp: datetime
    supporting_entity_id: Optional[str] = None


class StatusUpdateRequest(BaseModel):
    status: str  # OPEN | INVESTIGATING | RESOLVED


# ── Helper ────────────────────────────────────────────────────────────────────

def _get_incident_or_404(db: Session, workspace_id: UUID, incident_id: UUID) -> Incident:
    incident = db.query(Incident).filter(
        Incident.workspace_id == workspace_id,
        Incident.id == incident_id
    ).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/incidents", response_model=dict, summary="List all incidents")
async def list_incidents(
    status: Optional[str] = Query(None, description="Filter by status: OPEN, INVESTIGATING, RESOLVED"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("alerts:read")),
):
    """
    List all correlated security incidents for the workspace.
    Incidents are ordered by last_seen descending (most recent first).
    """
    query = db.query(Incident).filter(Incident.workspace_id == workspace.id)

    if status:
        valid_statuses = {"OPEN", "INVESTIGATING", "RESOLVED"}
        if status.upper() not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"status must be one of {valid_statuses}")
        query = query.filter(Incident.status == status.upper())

    if severity:
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if severity.upper() not in valid_severities:
            raise HTTPException(status_code=400, detail=f"severity must be one of {valid_severities}")
        query = query.filter(Incident.severity == severity.upper())

    total = query.count()
    incidents = query.order_by(desc(Incident.last_seen)).offset(offset).limit(limit).all()

    return {
        "incidents": [IncidentSummary.model_validate(inc).model_dump() for inc in incidents],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/incidents/{incident_id}", response_model=IncidentSummary, summary="Get incident summary")
async def get_incident(
    incident_id: UUID,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("alerts:read")),
):
    """
    Retrieve the full summary of a single incident including affected assets,
    MITRE techniques, correlation reasons, and status.
    """
    return IncidentSummary.model_validate(
        _get_incident_or_404(db, workspace.id, incident_id)
    )


@router.get("/incidents/{incident_id}/graph", response_model=dict, summary="Get attack graph")
async def get_attack_graph(
    incident_id: UUID,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("alerts:read")),
):
    """
    Returns a graph representation of the incident:
    - **nodes**: entities (IPs, URLs, domains, users, alerts, scans, MITRE techniques)
    - **edges**: directed relationships between entities

    Each node has: `id`, `type`, `label`, `risk_score`, `severity`
    Each edge has: `source`, `target`, `type` (e.g. triggered, belongs_to, mapped_to)
    """
    _get_incident_or_404(db, workspace.id, incident_id)
    try:
        graph = IncidentService.generate_attack_graph(db, workspace.id, incident_id)
        return graph
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph generation failed: {str(e)}")


@router.get("/incidents/{incident_id}/timeline", response_model=dict, summary="Get event timeline")
async def get_timeline(
    incident_id: UUID,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("alerts:read")),
):
    """
    Returns a chronological list of all security events related to this incident.
    Includes alerts, payload scans, and UBA anomalies sorted by timestamp.

    Each event has: `timestamp`, `event_type`, `entity`, `source`,
    `severity`, `risk_score`, `detection_result`, `related_evidence`,
    `mitre_technique`, `correlation_reason`
    """
    _get_incident_or_404(db, workspace.id, incident_id)
    try:
        timeline = IncidentService.generate_timeline(db, workspace.id, incident_id)
        return {"timeline": timeline, "total": len(timeline)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Timeline generation failed: {str(e)}")


@router.get("/incidents/{incident_id}/evidence", response_model=dict, summary="Get evidence records")
async def get_evidence(
    incident_id: UUID,
    source: Optional[str] = Query(None, description="Filter by source: ML_ENGINE, THREAT_INTEL, UBA, CORRELATION"),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("alerts:read")),
):
    """
    Returns all evidence records collected for this incident.
    Evidence is automatically gathered from ML detections, threat intel,
    UBA behavioral anomalies, and correlation engine findings.
    """
    _get_incident_or_404(db, workspace.id, incident_id)

    query = db.query(Evidence).filter(
        Evidence.workspace_id == workspace.id,
        Evidence.incident_alert_id == incident_id
    )
    if source:
        query = query.filter(Evidence.source == source.upper())

    evidence_records = query.order_by(desc(Evidence.timestamp)).all()

    return {
        "evidence": [EvidenceRecord.model_validate(e).model_dump() for e in evidence_records],
        "total": len(evidence_records),
    }


@router.get("/incidents/{incident_id}/attack-path", response_model=dict, summary="Get sequential attack path")
async def get_attack_path(
    incident_id: UUID,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("alerts:read")),
):
    """
    Returns a sequential step-by-step attack path derived from the incident timeline.
    Each step includes: `step`, `timestamp`, `type`, `label`, `description`

    This represents the attacker's progression through the kill chain.
    """
    _get_incident_or_404(db, workspace.id, incident_id)
    try:
        path = IncidentService.generate_attack_path(db, workspace.id, incident_id)
        return {"attack_path": path, "total_steps": len(path)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack path generation failed: {str(e)}")


@router.get("/incidents/{incident_id}/mitre", response_model=dict, summary="Get MITRE ATT&CK breakdown")
async def get_mitre_breakdown(
    incident_id: UUID,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("alerts:read")),
):
    """
    Returns the full MITRE ATT&CK technique breakdown for the incident.
    Techniques are aggregated from all associated scans and alerts.

    Each entry has: `technique_id`, `technique`, `tactic`, `count`, `risk_score`
    """
    incident = _get_incident_or_404(db, workspace.id, incident_id)

    # Aggregate MITRE from all linked scans
    from src.models.models import ScanHistory
    scans = db.query(ScanHistory).filter(
        ScanHistory.workspace_id == workspace.id,
        ScanHistory.incident_id == incident_id
    ).all()

    technique_map: dict = {}
    for scan in scans:
        for mapping in (scan.mitre_mappings or []):
            tid = mapping.get("technique_id")
            if tid:
                if tid not in technique_map:
                    technique_map[tid] = {
                        "technique_id": tid,
                        "technique": mapping.get("technique", tid),
                        "tactic": mapping.get("tactic", "Unknown"),
                        "count": 0,
                        "max_risk_score": 0,
                    }
                technique_map[tid]["count"] += 1
                technique_map[tid]["max_risk_score"] = max(
                    technique_map[tid]["max_risk_score"], scan.risk_score
                )

    # Include techniques listed directly in the incident model
    for tid in (incident.mitre_techniques or []):
        if tid not in technique_map:
            technique_map[tid] = {
                "technique_id": tid,
                "technique": tid,
                "tactic": "Unknown",
                "count": 1,
                "max_risk_score": incident.risk_score,
            }

    techniques = sorted(technique_map.values(), key=lambda x: -x["max_risk_score"])

    return {
        "techniques": techniques,
        "total": len(techniques),
        "incident_id": str(incident_id),
    }


@router.put("/incidents/{incident_id}/status", response_model=IncidentSummary, summary="Update incident status")
async def update_status(
    incident_id: UUID,
    body: StatusUpdateRequest,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("alerts:write")),
):
    """
    Update the investigation status of an incident.
    Valid values: `OPEN`, `INVESTIGATING`, `RESOLVED`
    """
    valid_statuses = {"OPEN", "INVESTIGATING", "RESOLVED"}
    if body.status.upper() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"status must be one of {valid_statuses}")

    incident = _get_incident_or_404(db, workspace.id, incident_id)
    incident.status = body.status.upper()
    db.commit()
    db.refresh(incident)
    return IncidentSummary.model_validate(incident)

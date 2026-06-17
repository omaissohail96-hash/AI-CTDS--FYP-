from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.api import deps
from src.models.models import ScanHistory, Workspace

router = APIRouter()


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)


def _serialize_scan(scan: ScanHistory) -> Dict[str, Any]:
    details = scan.details or {}
    return {
        "id": str(scan.id),
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "input_type": scan.input_type,
        "entity": scan.entity,
        "entities": scan.entities or [],
        "attack_type": scan.attack_type,
        "severity": scan.severity,
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "ml_confidence": scan.ml_confidence,
        "intelligence_hit": scan.intelligence_hit,
        "correlation_hit": scan.correlation_hit,
        "explanation": scan.explanation or details.get("explanation") or {},
        "mitre_mappings": scan.mitre_mappings or details.get("mitre_mappings") or [],
        "correlation": (details.get("intelligence") or {}).get("correlation") or {"detected": False},
    }


@router.get("/search")
async def search_threats(
    ip: Optional[str] = None,
    domain: Optional[str] = None,
    url: Optional[str] = None,
    email: Optional[str] = None,
    date_from: Optional[str] = Query(None, alias="from"),
    date_to: Optional[str] = Query(None, alias="to"),
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Dict[str, Any]:
    query = db.query(ScanHistory).filter(ScanHistory.workspace_id == workspace.id)

    entity_terms = [term for term in [ip, domain, url, email] if term]
    if entity_terms:
        query = query.filter(or_(*[ScanHistory.entity.ilike(f"%{term}%") for term in entity_terms]))
    if threat_type:
        query = query.filter(ScanHistory.attack_type.ilike(f"%{threat_type}%"))
    if severity:
        query = query.filter(or_(ScanHistory.severity == severity.upper(), ScanHistory.verdict == severity.upper()))

    start = _parse_date(date_from)
    end = _parse_date(date_to)
    if start:
        query = query.filter(ScanHistory.created_at >= start)
    if end:
        query = query.filter(ScanHistory.created_at <= end)

    sort_columns = {
        "created_at": ScanHistory.created_at,
        "risk_score": ScanHistory.risk_score,
        "severity": ScanHistory.severity,
        "attack_type": ScanHistory.attack_type,
    }
    sort_column = sort_columns.get(sort_by, ScanHistory.created_at)
    query = query.order_by(sort_column.asc() if sort_dir == "asc" else sort_column.desc())

    bounded_limit = min(max(limit, 1), 500)
    total = query.count()
    rows = query.offset(max(offset, 0)).limit(bounded_limit).all()
    incidents = [_serialize_scan(scan) for scan in rows]

    related_entities = sorted({
        entity
        for incident in incidents
        for entity in incident.get("entities", [])
        if entity
    })
    timeline = [
        {
            "timestamp": incident["created_at"],
            "entity": incident["entity"],
            "attack_type": incident["attack_type"],
            "risk_score": incident["risk_score"],
            "verdict": incident["verdict"],
        }
        for incident in incidents
    ]
    correlations = [
        {
            "scan_id": incident["id"],
            "correlation": incident["correlation"],
        }
        for incident in incidents
        if incident["correlation"].get("detected")
    ]

    return {
        "total": total,
        "limit": bounded_limit,
        "offset": offset,
        "incidents": incidents,
        "timeline": timeline,
        "related_entities": related_entities[:100],
        "correlation_findings": correlations,
    }

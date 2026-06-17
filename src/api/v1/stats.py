from datetime import datetime, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.api import deps
from src.models.models import AuditLog, ScanHistory, Workspace

router = APIRouter()

SEVERITY_ORDER = ["SAFE", "SUSPICIOUS", "HIGH", "CRITICAL"]
VERDICT_NORMALIZATION = {
    "SECURE": "SAFE",
    "SAFE": "SAFE",
    "LOW": "SAFE",
    "MEDIUM": "SUSPICIOUS",
    "SUSPICIOUS": "SUSPICIOUS",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "critical": "CRITICAL",
}


def _time_window(hours: int) -> datetime:
    return datetime.utcnow() - timedelta(hours=hours)


def _normalize_verdict(verdict: str | None) -> str:
    if not verdict:
        return "SAFE"
    return VERDICT_NORMALIZATION.get(verdict, verdict.upper())


def _resolve_time_window(db: Session, workspace_id, requested_hours: int) -> tuple[datetime | None, int, bool]:
    requested_start = _time_window(requested_hours)
    has_requested_data = db.query(ScanHistory.id).filter(
        ScanHistory.workspace_id == workspace_id,
        ScanHistory.created_at >= requested_start,
    ).first()
    if has_requested_data:
        return requested_start, requested_hours, False

    latest_scan = db.query(func.max(ScanHistory.created_at)).filter(
        ScanHistory.workspace_id == workspace_id,
    ).scalar()
    if latest_scan is None:
        return None, requested_hours, False

    fallback_start = latest_scan - timedelta(days=30)
    return fallback_start, 24 * 30, True


@router.get("/threat-summary")
async def get_threat_summary(
    hours: int = 24,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Dict[str, Any]:
    if hours == 0:
        total_scans = db.query(ScanHistory).filter(ScanHistory.workspace_id == workspace.id).count()
        grouped = db.query(
            ScanHistory.verdict,
            func.count(ScanHistory.id),
        ).filter(
            ScanHistory.workspace_id == workspace.id,
        ).group_by(ScanHistory.verdict).all()

        severity_counts = {level: 0 for level in SEVERITY_ORDER}
        for verdict, count in grouped:
            severity_counts[_normalize_verdict(verdict)] += count

        top_attack_rows = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace.id,
        ).all()

        attack_type_counts: Dict[str, int] = {}
        for scan in top_attack_rows:
            attack_type = scan.attack_type
            if not attack_type:
                details = scan.details or {}
                attack_type = details.get("attack_type")
                if not attack_type:
                    vector_details = details.get("vector_details") or []
                    if vector_details:
                        attack_type = vector_details[0].get("attack_type")
            if attack_type:
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

        api_usage = db.query(
            func.count(AuditLog.id)
        ).filter(
            AuditLog.workspace_id == workspace.id,
            AuditLog.module.in_(["gateway", "network_prevention"]),
        ).scalar() or 0

        alerts = db.query(func.count(ScanHistory.id)).filter(
            ScanHistory.workspace_id == workspace.id,
            ScanHistory.prevention_triggered == True,
        ).scalar() or 0

        return {
            "window_hours": 0,
            "effective_window_hours": 0,
            "fallback_used": False,
            "total_scans": total_scans,
            "severity_counts": severity_counts,
            "top_attack_types": [
                {"attack_type": attack_type, "count": count}
                for attack_type, count in sorted(attack_type_counts.items(), key=lambda item: item[1], reverse=True)[:5]
            ],
            "api_usage": {
                "requests": api_usage,
                "alerts": alerts,
                "quota_remaining": max(workspace.monthly_quota - total_scans, 0),
            },
        }

    time_window, effective_hours, fallback_used = _resolve_time_window(db, workspace.id, hours)
    if time_window is None:
        return {
            "window_hours": hours,
            "effective_window_hours": hours,
            "fallback_used": False,
            "total_scans": 0,
            "severity_counts": {level: 0 for level in SEVERITY_ORDER},
            "top_attack_types": [],
            "api_usage": {
                "requests": 0,
                "alerts": 0,
                "quota_remaining": workspace.monthly_quota,
            },
        }

    scans = db.query(ScanHistory).filter(
        ScanHistory.workspace_id == workspace.id,
        ScanHistory.created_at >= time_window,
    )

    total_scans = scans.count()
    grouped = db.query(
        ScanHistory.verdict,
        func.count(ScanHistory.id),
    ).filter(
        ScanHistory.workspace_id == workspace.id,
        ScanHistory.created_at >= time_window,
    ).group_by(ScanHistory.verdict).all()

    severity_counts = {level: 0 for level in SEVERITY_ORDER}
    for verdict, count in grouped:
        severity_counts[_normalize_verdict(verdict)] += count

    top_attack_rows = db.query(ScanHistory).filter(
        ScanHistory.workspace_id == workspace.id,
        ScanHistory.created_at >= time_window,
    ).all()

    attack_type_counts: Dict[str, int] = {}
    for scan in top_attack_rows:
        attack_type = scan.attack_type
        if not attack_type:
            details = scan.details or {}
            attack_type = details.get("attack_type")
            if not attack_type:
                vector_details = details.get("vector_details") or []
                if vector_details:
                    attack_type = vector_details[0].get("attack_type")
        if attack_type:
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

    api_usage = db.query(
        func.count(AuditLog.id)
    ).filter(
        AuditLog.workspace_id == workspace.id,
        AuditLog.module.in_(["gateway", "network_prevention"]),
        AuditLog.created_at >= time_window,
    ).scalar() or 0

    alerts = db.query(func.count(ScanHistory.id)).filter(
        ScanHistory.workspace_id == workspace.id,
        ScanHistory.created_at >= time_window,
        ScanHistory.prevention_triggered == True,
    ).scalar() or 0

    return {
        "window_hours": hours,
        "effective_window_hours": effective_hours,
        "fallback_used": fallback_used,
        "total_scans": total_scans,
        "severity_counts": severity_counts,
        "top_attack_types": [
            {"attack_type": attack_type, "count": count}
            for attack_type, count in sorted(attack_type_counts.items(), key=lambda item: item[1], reverse=True)[:5]
        ],
        "api_usage": {
            "requests": api_usage,
            "alerts": alerts,
            "quota_remaining": max(workspace.monthly_quota - total_scans, 0),
        },
    }



@router.get("/recent-scans")
async def get_recent_scans(
    limit: int = 10,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> List[Dict[str, Any]]:
    scans = db.query(ScanHistory).filter(
        ScanHistory.workspace_id == workspace.id
    ).order_by(ScanHistory.created_at.desc()).limit(min(limit, 50)).all()

    return [
        {
            "id": str(scan.id),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "input_type": scan.input_type,
            "entity": scan.entity,
            "attack_type": scan.attack_type,
            "severity": scan.severity,
            "verdict": _normalize_verdict(scan.verdict),
            "risk_score": scan.risk_score,
            "intelligence_hit": scan.intelligence_hit,
            "correlation_hit": scan.correlation_hit,
            "prevention_triggered": scan.prevention_triggered,
            "explanation": scan.explanation or {},
            "mitre_mappings": scan.mitre_mappings or [],
        }
        for scan in scans
    ]


@router.get("/threat-distribution")
async def get_threat_distribution(
    hours: int = 24,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Dict[str, Any]:
    if hours == 0:
        buckets = {
            "0-30": 0,
            "31-60": 0,
            "61-85": 0,
            "86-100": 0,
        }
        scans = db.query(ScanHistory.risk_score, ScanHistory.attack_type).filter(
            ScanHistory.workspace_id == workspace.id,
        ).all()

        attack_type_counts: Dict[str, int] = {}
        for score, attack_type in scans:
            numeric_score = float(score or 0)
            if numeric_score <= 30:
                buckets["0-30"] += 1
            elif numeric_score <= 60:
                buckets["31-60"] += 1
            elif numeric_score <= 85:
                buckets["61-85"] += 1
            else:
                buckets["86-100"] += 1

            if attack_type:
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

        return {
            "window_hours": 0,
            "effective_window_hours": 0,
            "fallback_used": False,
            "score_distribution": [{"range": key, "count": value} for key, value in buckets.items()],
            "attack_type_distribution": [
                {"attack_type": key, "count": value}
                for key, value in sorted(attack_type_counts.items(), key=lambda item: item[1], reverse=True)[:8]
            ],
        }

    time_window, effective_hours, fallback_used = _resolve_time_window(db, workspace.id, hours)
    if time_window is None:
        return {
            "window_hours": hours,
            "effective_window_hours": hours,
            "fallback_used": False,
            "score_distribution": [{"range": key, "count": 0} for key in ["0-30", "31-60", "61-85", "86-100"]],
            "attack_type_distribution": [],
        }

    buckets = {
        "0-30": 0,
        "31-60": 0,
        "61-85": 0,
        "86-100": 0,
    }
    scans = db.query(ScanHistory.risk_score, ScanHistory.attack_type).filter(
        ScanHistory.workspace_id == workspace.id,
        ScanHistory.created_at >= time_window,
    ).all()

    attack_type_counts: Dict[str, int] = {}
    for score, attack_type in scans:
        numeric_score = float(score or 0)
        if numeric_score <= 30:
            buckets["0-30"] += 1
        elif numeric_score <= 60:
            buckets["31-60"] += 1
        elif numeric_score <= 85:
            buckets["61-85"] += 1
        else:
            buckets["86-100"] += 1

        if attack_type:
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

    return {
        "window_hours": hours,
        "effective_window_hours": effective_hours,
        "fallback_used": fallback_used,
        "score_distribution": [{"range": key, "count": value} for key, value in buckets.items()],
        "attack_type_distribution": [
            {"attack_type": key, "count": value}
            for key, value in sorted(attack_type_counts.items(), key=lambda item: item[1], reverse=True)[:8]
        ],
    }


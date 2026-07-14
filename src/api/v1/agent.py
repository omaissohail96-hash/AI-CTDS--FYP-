"""
CyberGuard AI – Security Agent Endpoint
========================================

POST /api/v1/agent/analyze
  Accepts BOTH:
  - JWT authentication (dashboard users)
  - API key authentication (external customers)

The endpoint resolves to a Workspace regardless of auth method, so
workspace isolation is always enforced.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.api import deps
from src.api.deps import AuthContext, get_auth_context
from src.agent.orchestrator import SecurityAgent
from src.utils.saas_guard import SaaSGuard
from src.models.models import User, Workspace, ScanHistory
from src.utils.correlation import CorrelationEngine

router = APIRouter()


class AgentAnalyzeRequest(BaseModel):
    type: str = "auto"
    data: Any
    metadata: Optional[Dict[str, Any]] = None


@router.post("/analyze")
async def agent_analyze(
    request: AgentAnalyzeRequest,
    db: Session = Depends(deps.get_db),
    auth: AuthContext = Depends(deps.require_permissions("scans:create")),
):
    """
    Unified AI Agent endpoint with workspace-based isolation.

    Authentication:
      - Dashboard users  → Authorization: Bearer <JWT>
      - External clients → Authorization: Bearer cg_live_<token>
                         → X-API-Key: cg_live_<token>

    Workspace isolation is enforced regardless of the auth method.
    """
    workspace: Workspace = auth.workspace
    current_user: Optional[User] = auth.user  # None for API key auth

    try:
        # 1. SaaS guard: rate limit + quota
        SaaSGuard.check_rate_limit(db, workspace)
        SaaSGuard.check_quota(db, workspace)

        # 2. Run the SecurityAgent with workspace context
        agent = SecurityAgent(tenant_id=str(workspace.id))
        result = await agent.analyze_payload(
            db,
            {"type": request.type, "data": request.data},
            workspace=workspace,
            user_id=current_user.id if current_user else None,
        )

        # 3. Persist scan history (audit trail)
        from src.services.threat_intel import ThreatIntelService
        entities = result.get("entities") or CorrelationEngine.extract_entities(
            request.type, request.data
        )
        normalized_entity = ThreatIntelService.normalize_entity(
            entities[0] if entities else str(request.data)
        )
        top_vector = max(
            result.get("vector_details", []),
            key=lambda item: item.get("confidence", 0),
            default={},
        )
        prevention = result.get("prevention") or {}

        scan_log = ScanHistory(
            workspace_id=workspace.id,
            user_id=current_user.id if current_user else None,
            input_type=request.type,
            entity=normalized_entity,
            entities=entities,
            attack_type=result.get("attack_type") or top_vector.get("attack_type"),
            severity=result.get("severity") or top_vector.get("severity"),
            ml_confidence=int(top_vector.get("confidence", 0)),
            intelligence_hit=bool(result.get("intelligence", {}).get("threat_intel")),
            correlation_hit=bool(
                result.get("intelligence", {}).get("correlation", {}).get("detected")
            ),
            prevention_triggered=bool(prevention and prevention.get("alert")),
            risk_score=result["agent_verdict"]["score"],
            verdict=result["agent_verdict"]["label"],
            explanation=result.get("explanation") or {},
            mitre_mappings=result.get("mitre_mappings") or [],
            details=result,
        )
        db.add(scan_log)

        # 4. Increment API key success counter (if API key auth)
        if auth.api_key:
            from src.models.models import APIKey
            key = db.query(APIKey).filter(APIKey.id == auth.api_key.id).first()
            if key:
                key.successful_requests = (key.successful_requests or 0) + 1

        db.commit()
        return result

    except HTTPException:
        # Propagate rate-limit / quota / auth exceptions unchanged,
        # but increment the API key failure counter first.
        if auth.api_key:
            try:
                from src.models.models import APIKey
                key = db.query(APIKey).filter(APIKey.id == auth.api_key.id).first()
                if key:
                    key.failed_requests = (key.failed_requests or 0) + 1
                    db.commit()
            except Exception:
                pass
        raise
    except Exception as e:
        if auth.api_key:
            try:
                from src.models.models import APIKey
                key = db.query(APIKey).filter(APIKey.id == auth.api_key.id).first()
                if key:
                    key.failed_requests = (key.failed_requests or 0) + 1
                    db.commit()
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
def get_scan_history(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: AuthContext = Depends(deps.require_permissions("scans:read")),
):
    """
    Retrieve scan history for the current workspace.
    Accepts both JWT and API key authentication.
    """
    return (
        db.query(ScanHistory)
        .filter(ScanHistory.workspace_id == workspace.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(200)
        .all()
    )

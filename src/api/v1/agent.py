from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.api import deps
from src.agent.orchestrator import SecurityAgent
from src.utils.saas_guard import SaaSGuard
from src.models.models import Workspace, ScanHistory
from pydantic import BaseModel

router = APIRouter()

class AgentAnalyzeRequest(BaseModel):
    type: str = "auto"
    data: Any
    metadata: Optional[Dict[str, Any]] = None

@router.post("/analyze")
async def agent_analyze(
    request: AgentAnalyzeRequest,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace)
):
    """
    Unified AI Agent endpoint with Workspace-based isolation and logging.
    """
    try:
        # 1. SaaS Guard Enforcement (Quota and Rate Limiting)
        SaaSGuard.check_rate_limit(db, workspace)
        SaaSGuard.check_quota(db, workspace)

        # 2. Initialize agent with workspace context
        agent = SecurityAgent(tenant_id=str(workspace.id))
        
        # Run analysis
        result = await agent.analyze_payload(db, {"type": request.type, "data": request.data})
        
        # 3. Log to Scan History (Audit Trail)
        from src.services.threat_intel import ThreatIntelService
        normalized_entity = ThreatIntelService.normalize_entity(str(request.data))
        
        scan_log = ScanHistory(
            workspace_id=workspace.id,
            input_type=request.type,
            entity=normalized_entity,
            risk_score=result["agent_verdict"]["score"],
            verdict=result["agent_verdict"]["label"],
            details=result
        )
        db.add(scan_log)
        db.commit()
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history")
def get_scan_history(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace)
):
    """
    Retrieve scan history for the current workspace.
    """
    return db.query(ScanHistory).filter(ScanHistory.workspace_id == workspace.id).all()

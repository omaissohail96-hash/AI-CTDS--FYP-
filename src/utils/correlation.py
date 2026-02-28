import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from src.models.models import ScanHistory

class CorrelationEngine:
    @staticmethod
    def find_patterns(db: Session, workspace_id: uuid.UUID, entity: str) -> Dict[str, Any]:
        """
        Searches for the same entity across different vectors in the last 24 hours.
        """
        from src.services.threat_intel import ThreatIntelService
        normalized_entity = ThreatIntelService.normalize_entity(entity)
        
        time_window = datetime.utcnow() - timedelta(hours=24)
        
        # Find other scans in the same workspace with this entity mentioned in details
        # Entity could be in URL, Email content, or IP fields.
        previous_scans = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace_id,
            ScanHistory.entity == normalized_entity,
            ScanHistory.created_at > time_window
        ).all()
        
        correlated_events = []
        for scan in previous_scans:
            # ONLY consider previous scans as threats if they were actually high/critical risk
            if scan.risk_score > 60:
                correlated_events.append({
                    "scan_id": str(scan.id),
                    "vector": scan.input_type,
                    "risk_score": scan.risk_score,
                    "created_at": scan.created_at.isoformat()
                })
        
        if len(correlated_events) > 0:
            return {
                "detected": True,
                "pattern": "RECURRING_ENTITY_THREAT",
                "evidence_count": len(correlated_events),
                "events": correlated_events,
                "boost_factor": 1.2 # Increases risk score by 20%
            }
        
        return {"detected": False}

    @staticmethod
    def adjust_score(base_score: float, correlation: Dict[str, Any]) -> float:
        """
        Only boost score if the current scan is already somewhat suspicious (score > 40)
        and we have historical correlation.
        """
        if correlation.get("detected") and base_score > 40:
            return min(100.0, base_score * correlation["boost_factor"])
        return base_score

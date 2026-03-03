import asyncio
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from src.utils.scoring import ScoringEngine
from src.services.detection_service import DetectionService
from src.services.threat_intel import ThreatIntelService
from src.utils.correlation import CorrelationEngine
from src.utils.audit import AuditLogger

class SecurityAgent:
    """
    Enterprise-grade AI Security Agent Orchestrator.
    Handles task routing, model invocation, threat intelligence enrichment,
    and cross-vector correlation.
    """

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.scoring_engine = ScoringEngine()

    async def analyze_payload(self, db: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for checking threats with intelligence enrichment.
        """
        tasks = []
        input_type = payload.get("type", "auto").lower()
        data = payload.get("data")

        if not data:
            return {"error": "No data provided for analysis"}

        # 1. Threat Intelligence Enrichment (Pre-flight)
        # Check domain/IP against blacklists
        intel_result = None
        entity_to_check = data if isinstance(data, str) else str(data)
        if input_type in ["url", "network"] or "@" in entity_to_check:
            intel_result = ThreatIntelService.check_entity(db, entity_to_check)

        # 2. Routing Logic & Model Execution
        if input_type == "url":
            tasks.append(self._scan_url(data))
        elif input_type == "email":
            tasks.append(self._scan_email(data))
        elif input_type == "network":
            tasks.append(self._scan_network(data))
        elif input_type == "web":
            tasks.append(self._scan_web(data))
        else:
            if entity_to_check.startswith("http"):
                tasks.append(self._scan_url(data))
            elif "@" in entity_to_check:
                tasks.append(self._scan_email({"subject": "Auto-detected", "body": data}))

        # Execute ML models in parallel
        results = await asyncio.gather(*tasks) if tasks else []
        
        # 3. Base Aggregation & Scoring
        base_analysis = self.scoring_engine.calculate_risk(results)
        
        # 4. Cross-Vector Correlation (Post-flight)
        correlation = CorrelationEngine.find_patterns(db, uuid.UUID(self.tenant_id), entity_to_check)
        
        # 5. Final Score Adjustment
        base_score = base_analysis["score"]
        base_result = base_analysis # Renaming for clarity with new logic
        threat_intel = intel_result # Renaming for clarity with new logic

        final_score = base_score
        final_label = base_result["label"]
        final_summary = base_result["summary"]

        if threat_intel:
            final_score = max(final_score, 95)
            final_label = "CRITICAL"
            final_summary = f"CRITICAL: Entity detected in threat intelligence blacklist! (Threat: {threat_intel['threat_type']})"
            
        final_score = CorrelationEngine.adjust_score(final_score, correlation)
        if correlation.get("detected") and final_score > base_score:
            final_label = "HIGH" if final_score < 86 else "CRITICAL"
            if not threat_intel:
                final_summary = f"Security alert: Pattern detected across multiple vectors. Evidence count: {correlation['evidence_count']}"

        # Final Payload
        return {
            "agent_verdict": {
                "score": round(final_score, 2),
                "label": final_label,
                "summary": final_summary
            },
            "vector_details": results,
            "intelligence": {
                "threat_intel": intel_result,
                "correlation": correlation
            },
            "tenant_id": self.tenant_id,
            "status": "completed"
        }

    def _severity_rank(self, label: str) -> int:
        ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return ranks.get(label.lower(), 0)

    async def _scan_url(self, url: str):
        return DetectionService.analyze_url(url)

    async def _scan_email(self, email_data: Dict[str, Any]):
        return DetectionService.analyze_email(email_data)

    async def _scan_network(self, flow: Dict[str, Any]):
        return DetectionService.analyze_network(flow)

    async def _scan_web(self, payload: str):
        return DetectionService.analyze_web(payload)

import asyncio
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from src.models.models import Workspace
from src.utils.scoring import ScoringEngine
from src.services.detection_service import DetectionService
from src.services.threat_intel import ThreatIntelService
from src.services.alert_service import AlertService
from src.services.mitre_mapping_service import MITREMappingService
from src.services.threat_explanation_service import ThreatExplanationService
from src.services.user_behavior_analytics import UserBehaviorAnalyticsService
from src.utils.correlation import CorrelationEngine

class SecurityAgent:
    """
    Enterprise-grade AI Security Agent Orchestrator.
    Handles task routing, model invocation, threat intelligence enrichment,
    and cross-vector correlation.
    """

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.scoring_engine = ScoringEngine()

    async def analyze_payload(
        self,
        db: Session,
        payload: Dict[str, Any],
        workspace: Workspace | None = None,
        user_id: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        """
        Main entry point for checking threats with intelligence enrichment.
        """
        tasks = []
        input_type = payload.get("type", "auto").lower()
        data = payload.get("data")

        if not data:
            return {"error": "No data provided for analysis"}

        entities = CorrelationEngine.extract_entities(input_type, data)
        primary_entity = CorrelationEngine.primary_entity(entities, str(data) if isinstance(data, str) else "")

        intel_result = None
        for entity in entities or [primary_entity]:
            intel_result = ThreatIntelService.check_entity(db, entity)
            if intel_result:
                break

        if input_type == "url":
            tasks.append(self._scan_url(data))
        elif input_type == "email":
            tasks.append(self._scan_email(data))
        elif input_type == "network":
            tasks.append(self._scan_network(data, db, workspace))
        elif input_type == "web":
            tasks.append(self._scan_web(data))
        else:
            entity_to_check = primary_entity or (data if isinstance(data, str) else str(data))
            if entity_to_check.startswith("http"):
                tasks.append(self._scan_url(data))
            elif "@" in entity_to_check:
                tasks.append(self._scan_email({"subject": "Auto-detected", "body": data}))
            elif isinstance(data, dict):
                tasks.append(self._scan_network(data, db, workspace))

        results = await asyncio.gather(*tasks) if tasks else []
        correlation = CorrelationEngine.find_patterns(
            db,
            uuid.UUID(self.tenant_id),
            input_type=input_type,
            payload=data,
            entities=entities,
        )
        base_analysis = self.scoring_engine.calculate_risk(
            results,
            threat_intel=intel_result,
            correlation=correlation,
        )

        final_score = base_analysis["score"]
        final_label = base_analysis["label"]
        final_summary = base_analysis["summary"]
        behavior_risk = {"score": 0, "risk_level": "NORMAL", "explanation": None}
        if workspace:
            try:
                uba_event = UserBehaviorAnalyticsService.record_event(
                    db=db,
                    workspace_id=workspace.id,
                    user_id=user_id,
                    event_type="agent_analysis",
                    endpoint_accessed=f"agent/analyze:{input_type}",
                    metadata={"input_type": input_type},
                    commit=False,
                )
                behavior_risk = {
                    "score": int(uba_event.anomaly_score or 0),
                    "risk_level": uba_event.risk_level,
                    "explanation": uba_event.explanation,
                }
                if behavior_risk["score"] >= 61:
                    final_score = min(100, final_score + min(20, behavior_risk["score"] // 5))
                    final_summary = (
                        f"{final_summary} User behavior analytics also indicates "
                        f"{behavior_risk['risk_level'].lower()} account behavior."
                    )
            except Exception as exc:
                print(f"UBA SecurityAgent telemetry failed: {exc}")

        final_label = self._label_from_score(final_score)

        top_result = max(results, key=lambda item: item.get("confidence", 0), default={})
        prevention = (top_result.get("metadata") or {}).get("prevention") if top_result else None
        mitre_mappings = MITREMappingService.map_detection(
            input_type=input_type,
            attack_type=top_result.get("attack_type"),
            vector_details=results,
            metadata=top_result.get("metadata") or {},
        )

        # Generate alerts for high-risk detections
        generated_alert = None
        entity_type = self._determine_entity_type(input_type, data)
        
        if final_score >= 70 and workspace:  # Alert threshold
            primary_entity = CorrelationEngine.primary_entity(entities, str(data) if isinstance(data, str) else "")
            
            generated_alert = AlertService.generate_alert(
                db=db,
                workspace_id=workspace.id,
                user_id=None,  # Set by API layer if user context available
                scan_history_id=None,  # Will be set after scan is logged
                scan_result=top_result,
                entity=primary_entity or str(data),
                entity_type=entity_type,
                risk_score=int(final_score),
                intelligence_result=intel_result,
                correlation_result=correlation,
            )

        response = {
            "agent_verdict": {
                "score": round(final_score, 2),
                "label": final_label,
                "summary": final_summary
            },
            "vector_details": results,
            "intelligence": {
                "threat_intel": intel_result,
                "correlation": correlation,
                "user_behavior": behavior_risk,
            },
            "entities": entities,
            "attack_type": top_result.get("attack_type", "UNKNOWN"),
            "severity": top_result.get("severity", "LOW"),
            "prevention": prevention,
            "alert": {
                "generated": generated_alert is not None,
                "alert_id": str(generated_alert.id) if generated_alert else None,
                "severity": generated_alert.severity if generated_alert else None,
            } if workspace else None,
            "prevention_action": {
                "triggered": False,
                "mode": "IDS_ONLY",
                "message": "Automatic blocking is disabled for this IDS workflow. Review recommended actions manually.",
            } if workspace else None,
            "mitre_mappings": mitre_mappings,
            "user_behavior": behavior_risk,
            "tenant_id": self.tenant_id,
            "status": "completed"
        }
        response["explanation"] = ThreatExplanationService.generate(
            input_type=input_type,
            payload=data,
            result=response,
            mitre_mappings=mitre_mappings,
        )
        return response

    def _severity_rank(self, label: str) -> int:
        ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return ranks.get(label.lower(), 0)

    def _label_from_score(self, score: float) -> str:
        if score >= 86:
            return "CRITICAL"
        if score >= 61:
            return "HIGH"
        if score >= 31:
            return "SUSPICIOUS"
        return "SAFE"

    def _determine_entity_type(self, input_type: str, data: Any) -> str:
        """Determine entity type from input"""
        if input_type == "url":
            return "url"
        elif input_type == "email":
            return "email"
        elif input_type == "network":
            return "ip" if isinstance(data, dict) and "src_ip" in data else "network"
        elif input_type == "web":
            return "web_payload"
        else:
            return "unknown"

    async def _scan_url(self, url: str):
        return DetectionService.analyze_url(url)

    async def _scan_email(self, email_data: Dict[str, Any]):
        return DetectionService.analyze_email(email_data)

    async def _scan_network(self, flow: Dict[str, Any], db: Session | None = None, workspace: Workspace | None = None):
        return DetectionService.analyze_network(flow, db=db, workspace=workspace)

    async def _scan_web(self, payload: str):
        return DetectionService.analyze_web(payload)

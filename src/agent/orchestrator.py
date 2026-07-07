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
from src.services.false_positive_service import FalsePositiveFramework, SignalSet
from src.utils.correlation import CorrelationEngine


class SecurityAgent:
    """
    Enterprise-grade AI Security Agent Orchestrator.
    Handles task routing, model invocation, threat intelligence enrichment,
    cross-vector correlation, and false positive prevention.
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

        # ── UBA ─────────────────────────────────────────────────────────────
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
            except Exception as exc:
                print(f"UBA SecurityAgent telemetry failed: {exc}")

        # ── Weighted Ensemble Scoring ────────────────────────────────────────
        base_analysis = self.scoring_engine.calculate_risk(
            results,
            threat_intel=intel_result,
            correlation=correlation,
            uba=behavior_risk if behavior_risk["score"] > 0 else None,
        )

        final_score = base_analysis["score"]
        final_label = base_analysis["label"]
        final_summary = base_analysis["summary"]
        risk_contributions = base_analysis.get("contributions", {})
        explainable_factors = base_analysis.get("explainable_factors", [])

        final_label = self._label_from_score(final_score)

        top_result = max(results, key=lambda item: item.get("confidence", 0), default={})
        prevention = (top_result.get("metadata") or {}).get("prevention") if top_result else None
        mitre_mappings = MITREMappingService.map_detection(
            input_type=input_type,
            attack_type=top_result.get("attack_type"),
            vector_details=results,
            metadata=top_result.get("metadata") or {},
        )

        # ── False Positive Framework ─────────────────────────────────────────
        fp_signals = FalsePositiveFramework.detect_signals(
            risk_score=final_score,
            ml_score=float(top_result.get("confidence", 0)),
            threat_intel=intel_result,
            correlation=correlation,
            uba=behavior_risk if behavior_risk["score"] > 0 else None,
        )

        # ── Alert Generation ──────────────────────────────────────────────────
        generated_alert = None
        entity_type = self._determine_entity_type(input_type, data)

        if final_score >= 70 and workspace:
            generated_alert = AlertService.generate_alert(
                db=db,
                workspace_id=workspace.id,
                user_id=None,
                scan_history_id=None,
                scan_result=top_result,
                entity=primary_entity or str(data),
                entity_type=entity_type,
                risk_score=int(final_score),
                intelligence_result=intel_result,
                correlation_result=correlation,
            )

        # ── Prevention Decision (FP-safe) ─────────────────────────────────────
        should_block = False
        queue_for_review = False
        block_reason = ""
        if workspace and primary_entity:
            try:
                should_block, queue_for_review, block_reason = FalsePositiveFramework.should_block(
                    db=db,
                    workspace_id=workspace.id,
                    entity=primary_entity,
                    entity_type=entity_type,
                    risk_score=final_score,
                    signals=fp_signals,
                    threat_context={
                        "intelligence_hit": bool(intel_result),
                        "severity": top_result.get("severity", "LOW"),
                        "ml_confidence": float(top_result.get("confidence", 0)),
                    },
                )

                if queue_for_review and generated_alert:
                    FalsePositiveFramework.create_review_queue_item(
                        db=db,
                        workspace_id=workspace.id,
                        entity=primary_entity,
                        entity_type=entity_type,
                        risk_score=final_score,
                        signals=fp_signals,
                        risk_contributions=risk_contributions,
                        alert_id=generated_alert.id,
                    )
            except Exception as exc:
                print(f"FP framework evaluation failed: {exc}")

        # ── Generate Explanation ──────────────────────────────────────────────
        response = {
            "agent_verdict": {
                "score": int(final_score),
                "label": final_label,
                "summary": final_summary,
                "contributions": risk_contributions,
                "explainable_factors": explainable_factors,
                "confidence_calibration": base_analysis.get("confidence_calibration", 0),
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
                "in_review_queue": queue_for_review,
            } if workspace else None,
            "prevention_action": {
                "triggered": should_block,
                "queued_for_review": queue_for_review,
                "reason": block_reason,
                "signals": fp_signals,
                "message": (
                    f"Automated block triggered: {block_reason}" if should_block
                    else (f"Queued for human review: {block_reason}" if queue_for_review
                          else "No automated action taken. Monitoring mode.")
                ),
            } if workspace else None,
            "mitre_mappings": mitre_mappings,
            "user_behavior": behavior_risk,
            "tenant_id": self.tenant_id,
            "status": "completed",
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

import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from src.models.models import ScanHistory

class CorrelationEngine:
    @staticmethod
    def extract_entities(input_type: str, payload: Any) -> List[str]:
        from src.services.threat_intel import ThreatIntelService

        entities = ThreatIntelService.extract_entities(payload)
        if input_type == "network" and isinstance(payload, dict):
            for key in ("Source IP", "Destination IP", "src_ip", "dst_ip", "ip", "host", "domain"):
                value = payload.get(key)
                if value:
                    entities.extend(ThreatIntelService.extract_entities(str(value)))

        deduped = sorted({entity for entity in entities if entity})
        return deduped

    @staticmethod
    def primary_entity(entities: List[str], fallback: str = "") -> str:
        if entities:
            for entity in entities:
                if "://" not in entity:
                    return entity
            return entities[0]
        return fallback

    @staticmethod
    def find_patterns(
        db: Session,
        workspace_id: uuid.UUID,
        input_type: str,
        payload: Any,
        entities: List[str] | None = None,
    ) -> Dict[str, Any]:
        """
        Looks for repeated entities and cross-vector overlap in the last 24 hours.
        """
        entities = entities or CorrelationEngine.extract_entities(input_type, payload)
        normalized_entities = {entity.lower() for entity in entities}
        
        time_window = datetime.utcnow() - timedelta(hours=24)
        previous_scans = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace_id,
            ScanHistory.created_at > time_window
        ).all()
        
        correlated_events = []
        rules_triggered = set()
        repeated_entities = set()

        for scan in previous_scans:
            historical_entities = {
                entity.lower() for entity in (scan.entities or [])
            }
            overlapping = normalized_entities.intersection(historical_entities)
            if not overlapping:
                continue

            repeated_entities.update(overlapping)
            if scan.risk_score > 60:
                correlated_events.append({
                    "scan_id": str(scan.id),
                    "vector": scan.input_type,
                    "risk_score": scan.risk_score,
                    "created_at": scan.created_at.isoformat(),
                    "overlapping_entities": sorted(overlapping),
                    "attack_type": scan.attack_type,
                })

            if input_type == "email" and scan.input_type == "url":
                rules_triggered.add("email_contains_previously_flagged_url")
            elif input_type == "network" and scan.input_type in {"url", "web"}:
                rules_triggered.add("network_ip_matches_malicious_entity")
            elif input_type != scan.input_type:
                rules_triggered.add("cross_vector_repeat")
            else:
                rules_triggered.add("repeated_entity_24h")
        
        if correlated_events:
            boost_factor = 1.15
            if rules_triggered.intersection({"email_contains_previously_flagged_url", "network_ip_matches_malicious_entity"}):
                boost_factor = 1.3
            return {
                "detected": True,
                "pattern": "CROSS_VECTOR_ENTITY_CORRELATION",
                "evidence_count": len(correlated_events),
                "entities": sorted(repeated_entities),
                "rules_triggered": sorted(rules_triggered),
                "events": correlated_events,
                "boost_factor": boost_factor,
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

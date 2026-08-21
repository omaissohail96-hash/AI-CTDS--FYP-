import uuid
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from src.models.models import Evidence, Incident

class EvidenceEngine:
    @staticmethod
    def collect_evidence(
        db: Session,
        workspace_id: uuid.UUID,
        incident_alert_id: uuid.UUID,
        result: Dict[str, Any],
        supporting_entity_id: str | None = None
    ) -> List[Evidence]:
        """
        Extracts evidence items from scan results and saves them to the database.
        """
        evidence_items = []

        agent_verdict = result.get("agent_verdict", {})
        risk_score = agent_verdict.get("score", 0)
        risk_contributions = agent_verdict.get("contributions", {})

        # 1. ML Detection Evidence
        vector_details = result.get("vector_details", [])
        for detail in vector_details:
            vector_name = detail.get("vector", "ML Scanner")
            attack_type = detail.get("attack_type", "UNKNOWN")
            confidence = int(detail.get("confidence", 0) or detail.get("score", 0) or 0)
            
            # Treat as evidence if it's not normal traffic or has higher than baseline risk
            if attack_type != "NORMAL TRAFFIC" and confidence > 0:
                desc = (
                    f"Machine learning classified {vector_name} vector as "
                    f"{attack_type} with confidence of {confidence}%."
                )
                if detail.get("explanation"):
                    # Handle explanation dictionary or string
                    exp = detail.get("explanation")
                    if isinstance(exp, dict) and exp.get("description"):
                        desc += f" Details: {exp.get('description')}"
                    elif isinstance(exp, str):
                        desc += f" Details: {exp}"

                ev = Evidence(
                    workspace_id=workspace_id,
                    incident_alert_id=incident_alert_id,
                    evidence_type="ml_detection",
                    source=f"ML_{vector_name}",
                    description=desc,
                    value_indicator=attack_type,
                    confidence=confidence,
                    importance="HIGH" if confidence >= 70 else "MEDIUM",
                    supporting_entity_id=supporting_entity_id,
                )
                evidence_items.append(ev)

        # 2. Threat Intelligence Evidence
        intel = result.get("intelligence", {}).get("threat_intel")
        if intel and intel.get("hit"):
            entity_val = intel.get("entity_value")
            entity_type = intel.get("entity_type")
            threat_type = intel.get("threat_type")
            risk_level = intel.get("risk_level", "medium").upper()
            intel_source = intel.get("source", "Threat Intel Core")

            desc = (
                f"Threat intelligence match found on {intel_source} for {entity_type} '{entity_val}'. "
                f"Classified as {threat_type} with a {risk_level} risk rating."
            )

            ev = Evidence(
                workspace_id=workspace_id,
                incident_alert_id=incident_alert_id,
                evidence_type="threat_intelligence",
                source=intel_source,
                description=desc,
                value_indicator=entity_val,
                confidence=100,
                importance=risk_level,
                supporting_entity_id=supporting_entity_id,
            )
            evidence_items.append(ev)

        # 3. UBA Anomaly Evidence
        uba = result.get("intelligence", {}).get("user_behavior")
        if uba and uba.get("score", 0) > 0:
            uba_score = uba.get("score")
            risk_level = uba.get("risk_level", "NORMAL").upper()
            explanation = uba.get("explanation")
            desc_details = ""
            if explanation:
                if isinstance(explanation, dict):
                    desc_details = explanation.get("desc", explanation.get("reason", ""))
                else:
                    desc_details = str(explanation)
            
            desc = (
                f"User Behavior Analytics (UBA) anomaly detected. "
                f"Deviation score: {uba_score}/100. Status: {risk_level}."
            )
            if desc_details:
                desc += f" Anomaly reason: {desc_details}"

            ev = Evidence(
                workspace_id=workspace_id,
                incident_alert_id=incident_alert_id,
                evidence_type="uba_anomaly",
                source="UBA_Engine",
                description=desc,
                value_indicator=f"Score: {uba_score}",
                confidence=uba_score,
                importance="HIGH" if uba_score >= 70 else ("MEDIUM" if uba_score >= 30 else "LOW"),
                supporting_entity_id=supporting_entity_id,
            )
            evidence_items.append(ev)

        # 4. Correlation Evidence
        correlation = result.get("intelligence", {}).get("correlation")
        if correlation and correlation.get("detected"):
            rules = correlation.get("rules_triggered", [])
            events = correlation.get("events", [])
            pattern = correlation.get("pattern", "MULTI_VECTOR_CORRELATION")

            desc = (
                f"Correlation engine identified pattern: '{pattern}'. "
                f"Linked with {len(events)} previous scan event(s) in the last 24 hours. "
                f"Rules triggered: {', '.join(rules)}."
            )

            ev = Evidence(
                workspace_id=workspace_id,
                incident_alert_id=incident_alert_id,
                evidence_type="correlation",
                source="Correlation_Engine",
                description=desc,
                value_indicator=f"{len(events)} related events",
                confidence=100,
                importance="HIGH" if len(rules) > 1 else "MEDIUM",
                supporting_entity_id=supporting_entity_id,
            )
            evidence_items.append(ev)

        # 5. MITRE Mapping Evidence
        mitre_mappings = result.get("mitre_mappings", [])
        for mapping in mitre_mappings:
            tech_id = mapping.get("technique_id")
            tech_name = mapping.get("technique")
            tactic = mapping.get("tactic")
            tech_desc = mapping.get("description")

            desc = (
                f"Mapped to MITRE ATT&CK Technique: {tech_name} ({tech_id}) under "
                f"tactic '{tactic}'. Description: {tech_desc}"
            )

            ev = Evidence(
                workspace_id=workspace_id,
                incident_alert_id=incident_alert_id,
                evidence_type="mitre_mapping",
                source="MITRE_Mapper",
                description=desc,
                value_indicator=tech_id,
                confidence=100,
                importance=mapping.get("severity", "MEDIUM").upper(),
                supporting_entity_id=supporting_entity_id,
            )
            evidence_items.append(ev)

        # 6. Save items to DB
        for ev in evidence_items:
            db.add(ev)
        
        db.flush()
        return evidence_items

    @staticmethod
    def get_risk_explanation(db: Session, workspace_id: uuid.UUID, incident_id: uuid.UUID) -> Dict[str, Any]:
        """
        Compiles all evidence for an incident and yields a transparent risk breakdown.
        """
        # Fetch the incident
        incident = db.query(Incident).filter(
            Incident.id == incident_id,
            Incident.workspace_id == workspace_id
        ).first()

        if not incident:
            return {"error": "Incident not found"}

        # Fetch evidence records
        evidence_list = db.query(Evidence).filter(
            Evidence.workspace_id == workspace_id,
            Evidence.incident_alert_id == incident_id
        ).order_by(Evidence.timestamp.desc()).all()

        # Build transparent breakdown
        ml_score = 0
        threat_intel_score = 0
        uba_score = 0
        correlation_score = 0

        for ev in evidence_list:
            if ev.evidence_type == "ml_detection":
                ml_score = max(ml_score, ev.confidence)
            elif ev.evidence_type == "threat_intelligence":
                threat_intel_score = 20 if ev.importance == "HIGH" or ev.importance == "CRITICAL" else 10
            elif ev.evidence_type == "uba_anomaly":
                uba_score = max(uba_score, ev.confidence)
            elif ev.evidence_type == "correlation":
                correlation_score = 15

        breakdown = {
            "risk_score": incident.risk_score,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "factors": [
                {
                    "name": "Machine Learning Confidence",
                    "score": ml_score,
                    "description": "Baseline classifier prediction strength"
                },
                {
                    "name": "Threat Intelligence Enrichment",
                    "score": threat_intel_score,
                    "description": "Matches against known indicators of compromise (IoC)"
                },
                {
                    "name": "User Behavior Deviation",
                    "score": uba_score,
                    "description": "Anomalous activities compared to established baselines"
                },
                {
                    "name": "Entity Correlation",
                    "score": correlation_score,
                    "description": "Cross-vector relationships and temporal patterns"
                }
            ],
            "evidence": [
                {
                    "id": str(ev.id),
                    "evidence_type": ev.evidence_type,
                    "source": ev.source,
                    "description": ev.description,
                    "value": ev.value_indicator,
                    "confidence": ev.confidence,
                    "importance": ev.importance,
                    "timestamp": ev.timestamp.isoformat()
                }
                for ev in evidence_list
            ]
        }

        return breakdown

from __future__ import annotations

from typing import Any, Dict, List


class ThreatExplanationService:
    """
    Generates concise, analyst-friendly explanations from model output,
    intelligence enrichment, correlation findings, and rule evidence.
    """

    @staticmethod
    def generate(
        input_type: str,
        payload: Any,
        result: Dict[str, Any],
        mitre_mappings: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        verdict = result.get("agent_verdict", {})
        vector_details = result.get("vector_details") or []
        intelligence = result.get("intelligence") or {}
        threat_intel = intelligence.get("threat_intel")
        correlation = intelligence.get("correlation") or {}
        user_behavior = intelligence.get("user_behavior") or result.get("user_behavior") or {}
        top_vector = max(vector_details, key=lambda item: item.get("confidence", 0), default={})

        attack_type = result.get("attack_type") or top_vector.get("attack_type") or "UNKNOWN"
        confidence = float(top_vector.get("confidence") or verdict.get("score") or 0)
        confidence_level = ThreatExplanationService._confidence_level(confidence)

        evidence = ThreatExplanationService._build_evidence(
            input_type=input_type,
            top_vector=top_vector,
            threat_intel=threat_intel,
            correlation=correlation,
            user_behavior=user_behavior,
            mitre_mappings=mitre_mappings or [],
        )

        if verdict.get("label") == "SAFE":
            explanation = (
                f"This {input_type} scan was classified as safe because no high-risk detection rules, "
                f"threat intelligence hits, or recent correlation patterns were observed."
            )
        else:
            reasons = []
            if confidence:
                reasons.append(f"received a {round(confidence)}% model confidence score")
            if top_vector.get("metadata"):
                reasons.append("matched suspicious detection features or rules")
            if threat_intel:
                reasons.append("matched known threat intelligence indicators")
            if correlation.get("detected"):
                reasons.append("correlated with previous workspace incidents")
            if mitre_mappings:
                reasons.append(
                    "mapped to MITRE ATT&CK technique "
                    + ", ".join(mapping["technique_id"] for mapping in mitre_mappings[:2])
                )
            if int(user_behavior.get("score") or 0) >= 61:
                reasons.append("occurred during anomalous user behavior")

            reason_text = ", ".join(reasons) if reasons else "showed anomalous security signals"
            explanation = (
                f"This {input_type} was flagged as {attack_type} because it {reason_text}. "
                f"The final IDS risk verdict is {verdict.get('label', 'UNKNOWN')} with a score of "
                f"{verdict.get('score', 0)}."
            )

        return {
            "explanation": explanation,
            "evidence": evidence,
            "confidence_level": confidence_level,
            "recommended_action": ThreatExplanationService._recommended_action(
                verdict.get("label", "SAFE"),
                input_type,
                attack_type,
                bool(threat_intel),
                bool(correlation.get("detected")),
            ),
        }

    @staticmethod
    def _confidence_level(confidence: float) -> str:
        if confidence >= 85:
            return "HIGH"
        if confidence >= 60:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _build_evidence(
        input_type: str,
        top_vector: Dict[str, Any],
        threat_intel: Dict[str, Any] | None,
        correlation: Dict[str, Any],
        user_behavior: Dict[str, Any],
        mitre_mappings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        evidence = []
        if top_vector:
            evidence.append({
                "source": "ML Detection",
                "detail": f"{top_vector.get('vector', input_type).upper()} model classified the event as {top_vector.get('attack_type', 'UNKNOWN')}.",
                "confidence": top_vector.get("confidence", 0),
                "severity": top_vector.get("severity", "UNKNOWN"),
            })
            metadata = top_vector.get("metadata") or {}
            for key, value in metadata.items():
                evidence.append({
                    "source": "Detection Rule",
                    "detail": f"{key}: {value}",
                })

        if threat_intel:
            evidence.append({
                "source": "Threat Intelligence",
                "detail": f"Indicator matched {threat_intel.get('source', 'local intelligence')} as {threat_intel.get('threat_type', 'malicious')}.",
                "severity": threat_intel.get("risk_level", "UNKNOWN"),
            })

        if correlation.get("detected"):
            evidence.append({
                "source": "Correlation Engine",
                "detail": f"{correlation.get('evidence_count', 0)} related events matched rules: {', '.join(correlation.get('rules_triggered', []))}.",
            })

        if int(user_behavior.get("score") or 0) >= 31:
            explanation = user_behavior.get("explanation") or {}
            evidence.append({
                "source": "User Behavior Analytics",
                "detail": explanation.get("explanation", "User behavior deviated from established baseline."),
                "confidence": user_behavior.get("score", 0),
                "severity": user_behavior.get("risk_level", "SUSPICIOUS"),
            })

        for mapping in mitre_mappings:
            evidence.append({
                "source": "MITRE ATT&CK",
                "detail": f"{mapping['technique_id']} {mapping['technique']} under {mapping['tactic']}.",
                "severity": mapping.get("severity"),
            })

        return evidence

    @staticmethod
    def _recommended_action(
        label: str,
        input_type: str,
        attack_type: str,
        intelligence_hit: bool,
        correlation_hit: bool,
    ) -> str:
        if label == "SAFE":
            return "No immediate action required. Retain the scan for audit history."

        actions = {
            "url": "Do not visit the URL. Investigate the domain, capture screenshots in a sandbox, and notify affected users.",
            "email": "Quarantine the message, inspect headers and links, and warn recipients about possible phishing.",
            "network": "Investigate the source host, review adjacent flows, and validate whether the traffic is expected.",
            "web": "Review application logs, reproduce safely in a test environment, and prioritize patching vulnerable input handling.",
        }
        recommendation = actions.get(input_type, "Investigate the entity, preserve evidence, and escalate according to SOC severity policy.")
        if intelligence_hit:
            recommendation += " Treat the indicator as known malicious until disproven."
        if correlation_hit:
            recommendation += " Expand the investigation to correlated entities and prior incidents."
        if "SQL" in attack_type.upper() or "XSS" in attack_type.upper():
            recommendation += " Validate WAF and secure coding controls, but do not perform automatic blocking from this IDS workflow."
        return recommendation

"""
Enhanced threat explanation service for CyberGuard AI.
Generates structured, factor-based explanations for every detection decision.
"""

from typing import Any, Dict, List, Optional


class ThreatExplanationService:
    """
    Produces human-readable and machine-parseable explanations
    for threat detections, alert generation, and blocking decisions.
    """

    @staticmethod
    def generate(
        input_type: str,
        payload: Any,
        result: Dict[str, Any],
        mitre_mappings: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """
        Build a complete structured explanation for a scan result.

        Returns:
        {
            "headline": "Entity received a risk score of 92",
            "explanation": "Narrative paragraph...",
            "factors": [...],
            "risk_score": 92,
            "risk_contributions": {...},
            "confidence_level": "HIGH",
            "recommended_action": "...",
            "mitre_context": [...]
        }
        """
        verdict = result.get("agent_verdict", {})
        risk_score = int(verdict.get("score", 0))
        label = verdict.get("label", "SAFE")
        contributions = verdict.get("contributions") or {}
        explainable_factors = verdict.get("explainable_factors") or []
        raw_pillar_scores = result.get("agent_verdict", {}).get("raw_pillar_scores") or {}

        intel = result.get("intelligence", {})
        threat_intel = intel.get("threat_intel")
        correlation = intel.get("correlation")
        uba = intel.get("user_behavior")

        vector_details = result.get("vector_details") or []
        entity = str(payload) if isinstance(payload, str) else result.get("entities", ["unknown"])[0] if result.get("entities") else "unknown"

        # ── Build factor list ─────────────────────────────────────────────────
        factors = []

        # ML factors
        ml_contribution = contributions.get("ml", 0)
        ml_raw = raw_pillar_scores.get("ml", 0)
        if ml_raw > 0 or ml_contribution > 0:
            top_vector = max(vector_details, key=lambda r: r.get("confidence", 0), default={})
            attack_type = top_vector.get("attack_type", "Unknown threat")
            ml_conf = top_vector.get("confidence", ml_raw)
            factors.append({
                "signal": "ML Detection",
                "score": round(ml_raw, 1),
                "weight": 0.40,
                "contribution": round(ml_contribution, 1),
                "detail": f"{attack_type} classifier confidence: {ml_conf:.0f}%",
            })

        # Threat Intelligence factors
        ti_contribution = contributions.get("threat_intel", 0)
        ti_raw = raw_pillar_scores.get("threat_intel", 0)
        if threat_intel:
            factors.append({
                "signal": "Threat Intelligence",
                "score": round(ti_raw, 1),
                "weight": 0.25,
                "contribution": round(ti_contribution, 1),
                "detail": (
                    f"Matched {threat_intel.get('source', 'blacklist')} database: "
                    f"{threat_intel.get('threat_type', 'threat')} [{threat_intel.get('risk_level', 'unknown')} risk]"
                ),
            })

        # Correlation factors
        corr_contribution = contributions.get("correlation", 0)
        corr_raw = raw_pillar_scores.get("correlation", 0)
        if correlation and correlation.get("detected"):
            related = correlation.get("related_count", 0)
            rules = correlation.get("rules_triggered") or []
            factors.append({
                "signal": "Correlation Engine",
                "score": round(corr_raw, 1),
                "weight": 0.20,
                "contribution": round(corr_contribution, 1),
                "detail": f"{related} related detection(s) within 24h, {len(rules)} pattern rule(s) triggered",
            })

        # UBA factors
        uba_contribution = contributions.get("uba", 0)
        uba_raw = raw_pillar_scores.get("uba", 0)
        if uba and uba.get("score", 0) > 0:
            factors.append({
                "signal": "User Behavior Analytics",
                "score": round(uba_raw, 1),
                "weight": 0.15,
                "contribution": round(uba_contribution, 1),
                "detail": f"Anomaly score {uba.get('score', 0):.0f}, risk level: {uba.get('risk_level', 'NORMAL')}",
            })

        # ── Confidence Level ──────────────────────────────────────────────────
        confidence_level = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "SUSPICIOUS": "MEDIUM",
            "SAFE": "LOW",
        }.get(label, "LOW")

        # ── Recommended Action ────────────────────────────────────────────────
        recommended_action = ThreatExplanationService._recommend_action(
            label, threat_intel, correlation, uba
        )

        # ── MITRE Context ─────────────────────────────────────────────────────
        mitre_context = [
            f"{m.get('technique_id')} - {m.get('technique')}"
            for m in (mitre_mappings or [])[:4]
        ]

        # ── Narrative Explanation ─────────────────────────────────────────────
        narrative = ThreatExplanationService._build_narrative(
            entity, risk_score, label, factors, mitre_context
        )

        headline = f"Entity received a risk score of {risk_score} ({label})"

        return {
            "headline": headline,
            "explanation": narrative,
            "factors": factors,
            "risk_score": risk_score,
            "risk_contributions": contributions,
            "confidence_level": confidence_level,
            "recommended_action": recommended_action,
            "mitre_context": mitre_context,
            "explainable_factors": explainable_factors,
        }

    @staticmethod
    def _build_narrative(
        entity: str,
        risk_score: int,
        label: str,
        factors: List[Dict],
        mitre_context: List[str],
    ) -> str:
        if not factors:
            return f"Entity '{entity}' was analyzed and found to be {label.lower()} with a risk score of {risk_score}."

        factor_lines = []
        for f in factors:
            factor_lines.append(f"• {f['signal']}: {f['detail']} (contributes {f['contribution']:.1f} pts)")

        mitre_line = ""
        if mitre_context:
            mitre_line = f" This activity maps to MITRE ATT&CK techniques: {', '.join(mitre_context[:2])}."

        return (
            f"Entity '{entity}' received a risk score of {risk_score} because:\n"
            + "\n".join(factor_lines)
            + mitre_line
        )

    @staticmethod
    def _recommend_action(
        label: str,
        threat_intel: Optional[Dict],
        correlation: Optional[Dict],
        uba: Optional[Dict],
    ) -> str:
        if label == "CRITICAL":
            if threat_intel:
                return "Immediately block entity and escalate to security team. Blacklist confirmed by external intelligence."
            return "Block entity, escalate to incident response, and preserve evidence for forensics."

        if label == "HIGH":
            if correlation and correlation.get("detected"):
                return "Investigate correlated events, consider temporary block, and review related indicators."
            return "Quarantine entity, review scan history, and monitor for repeated activity."

        if label == "SUSPICIOUS":
            return "Monitor entity closely, review related activity, and report false positives if warranted."

        return "No immediate action required. Continue monitoring baseline activity."

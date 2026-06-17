from typing import Dict, Any, List

class ScoringEngine:
    """
    Unified Risk Scoring Engine for multi-vector threat detection.
    Computes a risk score from 0 to 100 and assigns threat labels.
    """
    
    LEVELS = {
        "SAFE": (0, 30),
        "SUSPICIOUS": (31, 60),
        "HIGH": (61, 85),
        "CRITICAL": (86, 100)
    }

    @staticmethod
    def calculate_risk(
        results: List[Dict[str, Any]],
        threat_intel: Dict[str, Any] | None = None,
        correlation: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        if not results:
            return {"score": 0, "label": "SAFE", "summary": "No threats analyzed."}

        scores = []
        
        for res in results:
            raw_confidence = res.get("confidence", 0)
            severity = res.get("severity", "LOW")
            metadata = res.get("metadata", {})
            
            if severity in {"LOW", "SECURE"}:
                score = 100 - raw_confidence
            else:
                score = raw_confidence
                if severity == "HIGH":
                    score = min(100, score * 1.2)
                elif severity == "MEDIUM":
                    score = min(100, score * 1.05)
                elif severity == "CRITICAL":
                    score = max(score, 90)

            prevention = metadata.get("prevention") or {}
            if prevention:
                score = max(score, prevention.get("anomaly_score", 0))
                if prevention.get("temporary_block"):
                    score = min(100, score + 10)
            
            scores.append(score)

        final_score = max(scores) if scores else 0

        if threat_intel:
            intel_boost = 35 if threat_intel.get("risk_level") == "critical" else 20
            final_score = min(100, max(final_score, threat_intel.get("confidence", 0)) + intel_boost)

        if correlation and correlation.get("detected"):
            correlation_boost = 10
            if correlation.get("rules_triggered"):
                correlation_boost += min(10, 2 * len(correlation["rules_triggered"]))
            final_score = min(100, final_score + correlation_boost)
        
        label = "SAFE"
        for l, (min_s, max_s) in ScoringEngine.LEVELS.items():
            if min_s <= final_score <= max_s:
                label = l
                break
                
        summary = ScoringEngine._generate_summary(final_score, label, results, threat_intel, correlation)

        return {
            "score": round(final_score, 2),
            "label": label,
            "summary": summary
        }

    @staticmethod
    def _generate_summary(
        score: float,
        label: str,
        results: List[Dict[str, Any]],
        threat_intel: Dict[str, Any] | None = None,
        correlation: Dict[str, Any] | None = None,
    ) -> str:
        threat_count = sum(1 for r in results if r.get("severity") in {"HIGH", "CRITICAL"})
        
        if label == "SAFE":
            return "No significant threats detected. Systems appear safe."
        
        if label == "CRITICAL":
            if threat_intel:
                return "Critical threat confirmed through blacklist intelligence. Immediate action required."
            return f"Critical vulnerability detected! {threat_count} high-severity vector(s) identified. Immediate action required."

        if correlation and correlation.get("detected"):
            return f"{label} risk due to correlated entities across vectors. Review repeated indicators and recent scans."

        return f"System identifies a {label.lower()} risk environment with {score}% confidence. Review flagged vectors."


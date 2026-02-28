from typing import Dict, Any, List

class ScoringEngine:
    """
    Unified Risk Scoring Engine for multi-vector threat detection.
    Computes a risk score from 0 to 100 and assigns threat labels.
    """
    
    LEVELS = {
        "LOW": (0, 30),
        "MEDIUM": (31, 60),
        "HIGH": (61, 85),
        "CRITICAL": (86, 100)
    }

    @staticmethod
    def calculate_risk(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not results:
            return {"score": 0, "label": "LOW", "summary": "No threats analyzed."}

        # Weighting logic (In a real SaaS, these would be configurable per tenant)
        # We give higher weight to confirmed phishing and network intrusions
        scores = []
        highest_severity = "LOW"
        
        for res in results:
            raw_confidence = res.get("confidence", 0)
            severity = res.get("severity", "LOW")
            
            # If the result is LEGITIMATE (LOW severity), the risk is low.
            # We invert the confidence: High confidence legitimate = Low risk score.
            if severity == "LOW":
                score = 100 - raw_confidence
            else:
                score = raw_confidence
                # Boost score if severity is high/critical
                if severity == "HIGH":
                    score = min(100, score * 1.2)
                elif severity == "CRITICAL":
                    score = max(score, 90) # Ensure critical is always high
            
            scores.append(score)

        # Final unified score (Max-biased average)
        # We don't just average because one critical threat should dominate
        final_score = max(scores) if scores else 0
        
        # Assign Label
        label = "LOW"
        for l, (min_s, max_s) in ScoringEngine.LEVELS.items():
            if min_s <= final_score <= max_s:
                label = l
                break
                
        # Generate Summary
        summary = ScoringEngine._generate_summary(final_score, label, results)

        return {
            "score": round(final_score, 2),
            "label": label,
            "summary": summary
        }

    @staticmethod
    def _generate_summary(score: float, label: str, results: List[Dict[str, Any]]) -> str:
        threat_count = sum(1 for r in results if r.get("severity") == "HIGH")
        
        if label == "LOW":
            return "No significant threats detected. Systems appear secure."
        
        if label == "CRITICAL":
            return f"Critical vulnerability detected! {threat_count} high-severity vector(s) identified. Immediate action required."
            
        return f"System identifies a {label} risk environment with {score}% confidence. Review flagged vectors."


"""
Weighted Ensemble Risk Scoring Engine for CyberGuard AI.

Replaces single-signal max-confidence scoring with a calibrated,
weighted ensemble across four independent detection pillars:

    Final Score = w_ml × ML Score
                + w_ti × Threat Intelligence Score
                + w_corr × Correlation Score
                + w_uba × UBA Score

Weights are fully configurable via settings.RISK_SCORE_WEIGHTS.
All scores are normalized to [0, 100] before weighting.
"""

from typing import Dict, Any, List, Optional, Tuple


class ScoringEngine:
    """
    Calibrated, explainable risk scoring engine.
    """

    LEVELS = {
        "SAFE":       (0, 30),
        "SUSPICIOUS": (31, 60),
        "HIGH":       (61, 85),
        "CRITICAL":   (86, 100),
    }

    # Severity multipliers for normalizing raw ML confidence
    _SEVERITY_MULTIPLIER = {
        "CRITICAL": 1.0,    # Already at ceiling
        "HIGH":     0.95,
        "MEDIUM":   0.80,
        "LOW":      0.50,
        "SECURE":   0.0,    # Invert — clean signal
        "SAFE":     0.0,
    }

    @classmethod
    def _get_weights(cls) -> Dict[str, float]:
        """Load weights from settings, falling back to sensible defaults."""
        try:
            from src.core.config import settings
            return settings.risk_weights
        except Exception:
            return {"ml": 0.40, "threat_intel": 0.25, "correlation": 0.20, "uba": 0.15}

    # ── ML Score Extraction ───────────────────────────────────────────────────

    @classmethod
    def _extract_ml_score(cls, results: List[Dict[str, Any]]) -> Tuple[float, str]:
        """
        Compute the ML pillar score from all detector results.
        Uses weighted-average across detectors (not just max).

        Returns (normalized_score_0_100, detail_string)
        """
        if not results:
            return 0.0, "No ML detectors ran"

        weighted_scores = []
        details = []

        for res in results:
            raw_confidence = float(res.get("confidence", 0))
            severity = (res.get("severity") or "LOW").upper()
            attack_type = res.get("attack_type", "UNKNOWN")

            # Convert raw confidence to a threat score
            if severity in {"SECURE", "SAFE", "LOW"}:
                # Low/clean detections contribute low threat scores
                threat_score = max(0.0, 100.0 - raw_confidence) * cls._SEVERITY_MULTIPLIER.get(severity, 0.3)
            else:
                threat_score = raw_confidence * cls._SEVERITY_MULTIPLIER.get(severity, 0.8)
                if severity == "CRITICAL":
                    threat_score = max(threat_score, 85.0)
                elif severity == "HIGH":
                    threat_score = max(threat_score, 60.0)

            # Check prevention metadata for additional signals
            prevention = (res.get("metadata") or {}).get("prevention") or {}
            if prevention.get("anomaly_score"):
                threat_score = max(threat_score, float(prevention["anomaly_score"]))
            if prevention.get("temporary_block"):
                threat_score = min(100.0, threat_score + 10.0)

            weighted_scores.append(min(100.0, threat_score))
            if threat_score > 30:
                details.append(f"{attack_type} detector: {threat_score:.0f}% threat")

        # Ensemble: weighted average with heavier weight on higher scores
        if not weighted_scores:
            return 0.0, "No threat signals"

        # Sort descending so the most severe signal has the most influence
        weighted_scores.sort(reverse=True)
        n = len(weighted_scores)
        weights = [1.0 / (i + 1) for i in range(n)]
        total_weight = sum(weights)
        final_ml = sum(s * w for s, w in zip(weighted_scores, weights)) / total_weight

        return min(100.0, final_ml), "; ".join(details) or "ML baseline"

    # ── Threat Intel Score ────────────────────────────────────────────────────

    @classmethod
    def _extract_ti_score(cls, threat_intel: Optional[Dict]) -> Tuple[float, str]:
        """
        Convert a threat intelligence result to a 0-100 score.
        Returns (score, detail)
        """
        if not threat_intel:
            return 0.0, "No threat intelligence match"

        risk_level = (threat_intel.get("risk_level") or "low").lower()
        base_scores = {
            "critical": 100.0,
            "high": 85.0,
            "medium": 60.0,
            "low": 35.0,
        }
        score = base_scores.get(risk_level, 40.0)
        source = threat_intel.get("source", "unknown")
        threat_type = threat_intel.get("threat_type", "unknown")
        return score, f"TI blacklist match ({source}): {threat_type} [{risk_level}]"

    # ── Correlation Score ─────────────────────────────────────────────────────

    @classmethod
    def _extract_correlation_score(cls, correlation: Optional[Dict]) -> Tuple[float, str]:
        """
        Convert correlation engine results to a 0-100 score.
        Returns (score, detail)
        """
        if not correlation or not correlation.get("detected"):
            return 0.0, "No correlated patterns"

        rules_triggered = correlation.get("rules_triggered") or []
        related_count = correlation.get("related_count", 0)

        # Base score for any correlation hit
        score = 50.0
        # Bonus per rule triggered (up to 30 additional points)
        score += min(30.0, len(rules_triggered) * 8.0)
        # Bonus for high related event count
        if related_count >= 10:
            score += 20.0
        elif related_count >= 5:
            score += 10.0
        elif related_count >= 3:
            score += 5.0

        detail = f"{len(rules_triggered)} correlation rule(s) triggered, {related_count} related events"
        return min(100.0, score), detail

    # ── UBA Score ─────────────────────────────────────────────────────────────

    @classmethod
    def _extract_uba_score(cls, uba: Optional[Dict]) -> Tuple[float, str]:
        """
        Convert user behavior analytics result to a 0-100 score.
        Returns (score, detail)
        """
        if not uba:
            return 0.0, "No UBA data"

        anomaly_score = float(uba.get("score", 0))
        risk_level = (uba.get("risk_level") or "NORMAL").upper()

        # Map risk level to minimum floor
        floors = {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40, "LOW": 20, "NORMAL": 0}
        floor = floors.get(risk_level, 0)
        score = max(anomaly_score, float(floor))

        detail = f"UBA anomaly score {score:.0f} ({risk_level})"
        return min(100.0, score), detail

    # ── Calibration ───────────────────────────────────────────────────────────

    @staticmethod
    def _calibrate_confidence(raw_score: float) -> float:
        """
        Platt-scaling-inspired confidence calibration.
        Maps raw weighted score to a calibrated probability estimate.
        Reduces overconfidence in mid-range scores.
        """
        import math
        # Sigmoid-based calibration centered at 50
        x = (raw_score - 50.0) / 15.0
        calibrated = 1.0 / (1.0 + math.exp(-x))
        # Map back to 0-100 range
        return round(calibrated * 100.0, 2)

    # ── Main Entry Point ──────────────────────────────────────────────────────

    @classmethod
    def calculate_risk(
        cls,
        results: List[Dict[str, Any]],
        threat_intel: Optional[Dict] = None,
        correlation: Optional[Dict] = None,
        uba: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Compute a calibrated, explainable risk score from all detection pillars.

        Returns:
        {
            "score": 92,
            "label": "CRITICAL",
            "summary": "...",
            "contributions": {"ml": 40, "threat_intel": 25, "correlation": 18, "uba": 9},
            "raw_pillar_scores": {"ml": 88, "threat_intel": 100, "correlation": 85, "uba": 66},
            "confidence_calibration": 0.87,
            "explainable_factors": ["RF phishing score: 88", "TI blacklist match (abuseipdb): phishing [critical]", ...]
        }
        """
        if not results and not threat_intel and not correlation and not uba:
            return {
                "score": 0,
                "label": "SAFE",
                "summary": "No threats analyzed.",
                "contributions": {"ml": 0, "threat_intel": 0, "correlation": 0, "uba": 0},
                "raw_pillar_scores": {"ml": 0, "threat_intel": 0, "correlation": 0, "uba": 0},
                "confidence_calibration": 0.0,
                "explainable_factors": [],
            }

        weights = cls._get_weights()

        # Extract each pillar score
        ml_score, ml_detail = cls._extract_ml_score(results)
        ti_score, ti_detail = cls._extract_ti_score(threat_intel)
        corr_score, corr_detail = cls._extract_correlation_score(correlation)
        uba_score, uba_detail = cls._extract_uba_score(uba)

        raw_scores = {
            "ml": round(ml_score, 1),
            "threat_intel": round(ti_score, 1),
            "correlation": round(corr_score, 1),
            "uba": round(uba_score, 1),
        }

        # Weighted sum
        final_raw = (
            ml_score * weights["ml"]
            + ti_score * weights["threat_intel"]
            + corr_score * weights["correlation"]
            + uba_score * weights["uba"]
        )
        final_score = round(min(100.0, max(0.0, final_raw)), 2)

        # Per-pillar contributions (weight × pillar_score → portion of final score)
        contributions = {
            "ml":           round(ml_score * weights["ml"], 1),
            "threat_intel": round(ti_score * weights["threat_intel"], 1),
            "correlation":  round(corr_score * weights["correlation"], 1),
            "uba":          round(uba_score * weights["uba"], 1),
        }

        calibration = cls._calibrate_confidence(final_score)
        label = cls._label_from_score(final_score)

        # Build explainable factors list (non-zero signals only)
        factors = []
        if ml_score > 5:
            factors.append(ml_detail)
        if ti_score > 0:
            factors.append(ti_detail)
        if corr_score > 0:
            factors.append(corr_detail)
        if uba_score > 0:
            factors.append(uba_detail)

        summary = cls._generate_summary(final_score, label, results, threat_intel, correlation)

        return {
            "score": int(final_score),
            "label": label,
            "summary": summary,
            "contributions": contributions,
            "raw_pillar_scores": raw_scores,
            "confidence_calibration": calibration,
            "explainable_factors": factors,
        }

    @classmethod
    def _label_from_score(cls, score: float) -> str:
        for label, (lo, hi) in cls.LEVELS.items():
            if lo <= score <= hi:
                return label
        return "SAFE"

    @staticmethod
    def _generate_summary(
        score: float,
        label: str,
        results: List[Dict],
        threat_intel: Optional[Dict],
        correlation: Optional[Dict],
    ) -> str:
        threat_count = sum(1 for r in results if (r.get("severity") or "").upper() in {"HIGH", "CRITICAL"})

        if label == "SAFE":
            return "No significant threats detected. Systems appear safe."

        if label == "CRITICAL":
            if threat_intel:
                return "Critical threat confirmed through blacklist intelligence. Immediate action required."
            return (
                f"Critical vulnerability detected! {threat_count} high-severity vector(s) identified. "
                "Immediate action required."
            )

        if correlation and correlation.get("detected"):
            return (
                f"{label} risk due to correlated entities across vectors. "
                "Review repeated indicators and recent scans."
            )

        return (
            f"System identifies a {label.lower()} risk environment with {score:.0f}% confidence. "
            "Review flagged vectors."
        )

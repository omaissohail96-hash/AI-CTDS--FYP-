"""Web-attack service backed exclusively by the validated trained ML pipeline."""

from __future__ import annotations

from typing import Any

from detectors.web_detector_ml import predict_web_attack_ml


class WebAttackMLService:
    """Expose trained-model web payload analysis to the detection service."""

    @staticmethod
    def analyze_web(payload: str, **_: Any) -> dict[str, Any]:
        result = predict_web_attack_ml(payload)
        return {
            "vector": "WEB",
            "prediction": result["prediction"],
            "attack_type": result["attack_type"],
            "confidence": result["confidence"],
            "severity": result["severity"],
            "metadata": {
                "ml_features": result["important_features"],
                "ml_explanation": result["explanation"],
                "model_version": result["model_version"],
            },
        }

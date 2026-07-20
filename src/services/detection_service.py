from typing import Dict, Any
from detectors.url_feature_extractor import extract_url_features
from detectors.url_detector import predict_url_phishing
from detectors.email_detector import predict_email_attack
from detectors.network_detectors import predict_network_attacks
from src.services.web_attack_ml_service import WebAttackMLService
from sqlalchemy.orm import Session

from src.models.models import Workspace
from src.services.network_defense import NetworkDefenseService


class DetectionService:
    """
    Service Layer wrapper for underlying ML models.
    Encapsulates data transformation and model invocation logic.
    """

    @staticmethod
    def analyze_url(url: str) -> Dict[str, Any]:
        features = extract_url_features(url)
        res = predict_url_phishing(features, url)
        res["vector"] = "URL"
        res["metadata"] = {"features_extracted": len(features)}
        return res

    @staticmethod
    def analyze_email(email_data) -> Dict[str, Any]:
        """Accept both plain strings (treat as body) and structured dicts."""
        if isinstance(email_data, str):
            subject = ""
            body = email_data
        else:
            subject = email_data.get("subject", "")
            body = email_data.get("body", "") or email_data.get("content", "")
        res = predict_email_attack(subject, body)
        res["vector"] = "EMAIL"
        return res

    @staticmethod
    def analyze_network(
        flow_features: Dict[str, Any],
        db: Session | None = None,
        workspace: Workspace | None = None,
    ) -> Dict[str, Any]:
        res = predict_network_attacks(flow_features)
        res["vector"] = "NETWORK"
        if db and workspace:
            prevention = NetworkDefenseService.evaluate_flow(db, workspace, flow_features)
            res.setdefault("metadata", {})
            res["metadata"]["prevention"] = prevention
            if prevention["anomaly_score"] >= 45:
                res["severity"] = "CRITICAL" if prevention["severity"] == "CRITICAL" else "HIGH"
                res["confidence"] = max(float(res.get("confidence", 0)), float(prevention["anomaly_score"]))
                if res["attack_type"] == "NORMAL TRAFFIC":
                    res["attack_type"] = "NETWORK ANOMALY"
        return res

    @staticmethod
    def analyze_web(payload: str) -> Dict[str, Any]:
        return WebAttackMLService.analyze_web(payload)

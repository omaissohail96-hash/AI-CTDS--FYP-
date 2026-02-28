from typing import Dict, Any
from detectors.url_feature_extractor import extract_url_features
from detectors.url_detector import predict_url_phishing
from detectors.email_detector import predict_email_attack
from detectors.network_detectors import predict_network_attacks
from detectors.web_detector import predict_web_attack

class DetectionService:
    """
    Service Layer wrapper for underlying ML models.
    Encapsulates data transformation and model invocation logic.
    """

    @staticmethod
    def analyze_url(url: str) -> Dict[str, Any]:
        features = extract_url_features(url)
        res = predict_url_phishing(features)
        res["vector"] = "URL"
        res["metadata"] = {"features_extracted": len(features)}
        return res

    @staticmethod
    def analyze_email(email_data: Dict[str, Any]) -> Dict[str, Any]:
        res = predict_email_attack(
            email_data.get("subject", ""), 
            email_data.get("body", "")
        )
        res["vector"] = "EMAIL"
        return res

    @staticmethod
    def analyze_network(flow_features: Dict[str, Any]) -> Dict[str, Any]:
        res = predict_network_attacks(flow_features)
        res["vector"] = "NETWORK"
        return res

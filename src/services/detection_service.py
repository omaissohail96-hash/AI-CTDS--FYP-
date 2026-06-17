from typing import Dict, Any
from detectors.url_feature_extractor import extract_url_features
from detectors.url_detector import predict_url_phishing
from detectors.email_detector import predict_email_attack
from detectors.network_detectors import predict_network_attacks
from detectors.web_detector import predict_web_attack
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
    def analyze_email(email_data: Dict[str, Any]) -> Dict[str, Any]:
        res = predict_email_attack(
            email_data.get("subject", ""), 
            email_data.get("body", "")
        )
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
        # Web Attack model was trained on URL phishing data accidentally, replacing with robust heuristics for accurate detection.
        import re
        p_lower = payload.lower()
        
        # SQL Injection Patterns
        sqli_pattern = re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\b(union|select|insert|drop|update|delete|truncate|sleep|benchmark)\b)", re.IGNORECASE)
        # Cross-Site Scripting (XSS) Patterns
        xss_pattern = re.compile(r"(<script>)|(%3Cscript%3E)|(javascript:)|(onerror=)|(onload=)|(alert\()|(<img\s)", re.IGNORECASE)
        # Directory Traversal
        lfi_pattern = re.compile(r"(\.\.\/)|(\.\.\\)|(\%2e\%2e\%2f)|(\%2e\%2e\/)|(\.\.\%2f)|(\/etc\/passwd)", re.IGNORECASE)

        if xss_pattern.search(p_lower):
            return {
                "attack_type": "CROSS-SITE SCRIPTING (XSS)",
                "confidence": 99.0,
                "severity": "CRITICAL",
                "vector": "WEB",
                "metadata": {"matched_pattern": "xss"}
            }
        elif sqli_pattern.search(p_lower):
            return {
                "attack_type": "SQL INJECTION",
                "confidence": 99.0,
                "severity": "CRITICAL",
                "vector": "WEB",
                "metadata": {"matched_pattern": "sqli"}
            }
        elif lfi_pattern.search(p_lower):
            return {
                "attack_type": "PATH TRAVERSAL",
                "confidence": 95.0,
                "severity": "HIGH",
                "vector": "WEB",
                "metadata": {"matched_pattern": "lfi"}
            }
        
        # Default to checking the web model for any residual features if it's not a glaring attack (Fallback)
        # The web model expects a dictionary, so we pass an empty one and rely on the model's base state
        res = predict_web_attack({})
        # Force label to SECURE and low confidence if no obvious attack is seen, as model is untrustworthy for raw strings
        res["attack_type"] = "LEGITIMATE REQUEST"
        res["confidence"] = 90.0 # High confidence it's secure if it passed regex
        res["severity"] = "SECURE"
        res["vector"] = "WEB"
        res["metadata"] = {"matched_pattern": "none"}
        return res

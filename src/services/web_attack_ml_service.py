from typing import Dict, Any
import re
from detectors.web_detector_ml import predict_web_attack_ml
from sqlalchemy.orm import Session
from src.models.models import Workspace

class WebAttackMLService:
    """
    Hybrid Web Attack Detection Service.
    Combines true ML (TF-IDF + Random Forest) with robust regular expression heuristics.
    """

    @staticmethod
    def _run_regex_heuristics(payload: str) -> Dict[str, Any] | None:
        p_lower = payload.lower()
        
        sqli_pattern = re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\b(union|select|insert|drop|update|delete|truncate|sleep|benchmark)\b)", re.IGNORECASE)
        xss_pattern = re.compile(r"(<script>)|(%3Cscript%3E)|(javascript:)|(onerror=)|(onload=)|(alert\()|(<img\s)", re.IGNORECASE)
        lfi_pattern = re.compile(r"(\.\.\/)|(\.\.\\)|(\%2e\%2e\%2f)|(\%2e\%2e\/)|(\.\.\%2f)|(\/etc\/passwd)", re.IGNORECASE)

        if xss_pattern.search(p_lower):
            return {
                "attack_type": "CROSS-SITE SCRIPTING (XSS)",
                "confidence": 95.0,
                "severity": "CRITICAL",
                "source": "regex_heuristic"
            }
        elif sqli_pattern.search(p_lower):
            return {
                "attack_type": "SQL INJECTION",
                "confidence": 95.0,
                "severity": "CRITICAL",
                "source": "regex_heuristic"
            }
        elif lfi_pattern.search(p_lower):
            return {
                "attack_type": "PATH TRAVERSAL",
                "confidence": 90.0,
                "severity": "HIGH",
                "source": "regex_heuristic"
            }
        return None

    @staticmethod
    def analyze_web(payload: str, db: Session | None = None, workspace: Workspace | None = None) -> Dict[str, Any]:
        """
        Runs both ML and Regex heuristics, combining results for a hybrid decision.
        """
        # 1. Run Machine Learning Model
        ml_result = predict_web_attack_ml(payload)
        
        # 2. Run Heuristics
        regex_result = WebAttackMLService._run_regex_heuristics(payload)
        
        # 3. Hybrid Consensus Logic
        final_result = {
            "vector": "WEB",
            "prediction": ml_result["prediction"],
            "attack_type": ml_result["attack_type"],
            "confidence": ml_result["confidence"],
            "severity": ml_result["severity"],
            "metadata": {
                "ml_features": ml_result["important_features"],
                "ml_explanation": ml_result["explanation"],
                "regex_triggered": False
            }
        }
        
        if regex_result:
            final_result["metadata"]["regex_triggered"] = True
            
            # If Regex detects an attack, but ML says SAFE, we trust Regex (Fail-Safe)
            if ml_result["prediction"] == "SAFE":
                final_result["prediction"] = "MALICIOUS"
                final_result["attack_type"] = regex_result["attack_type"]
                final_result["confidence"] = regex_result["confidence"]
                final_result["severity"] = regex_result["severity"]
                final_result["metadata"]["hybrid_decision"] = "regex_override"
            else:
                # If both detect, combine confidence and use the more critical severity
                final_result["confidence"] = min(100.0, ml_result["confidence"] + 10.0) # Boost confidence
                final_result["metadata"]["hybrid_decision"] = "consensus"
                
        return final_result

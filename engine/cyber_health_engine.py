from detectors.web_detector import predict_web_attack
from detectors.network_detectors import predict_network_attacks
from detectors.email_detector import predict_email_attack
from detectors.url_feature_extractor import extract_url_features


def run_cyber_health_check(web_payload, network_flow, email_data):
    results = {}

    try:
        results["web"] = predict_web_attack(web_payload)
    except Exception as exc:
        results["web"] = {"attack_type": "UNKNOWN", "confidence": 0, "severity": "LOW", "error": str(exc)}

    try:
        results["network"] = predict_network_attacks(network_flow)
    except Exception as exc:
        results["network"] = {"attack_type": "UNKNOWN", "confidence": 0, "severity": "LOW", "error": str(exc)}

    try:
        if isinstance(email_data, dict):
            subject = email_data.get("subject", "")
            body = email_data.get("body", "")
        elif isinstance(email_data, tuple) and len(email_data) == 2:
            subject, body = email_data
        else:
            subject = ""
            body = str(email_data)
        results["email"] = predict_email_attack(subject, body)
    except Exception as exc:
        results["email"] = {"attack_type": "UNKNOWN", "confidence": 0, "severity": "LOW", "error": str(exc)}

    return results

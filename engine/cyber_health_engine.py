from detectors.web_detector import predict_web_attack
from detectors.network_detectors import predict_network_attacks
from detectors.email_detector import predict_email_attack
from detectors.url_feature_extractor import extract_url_features

def run_cyber_health_check(url, network_flow, email_data):
    results = {}

    # 🌐 WEB ATTACK
    url_features = extract_url_features(url)
    results["web"] = predict_web_attack(url_features)

    # 🌐 NETWORK
    results["network"] = predict_network_attacks(network_flow)

    # 📧 EMAIL
    results["email"] = predict_email_attack(
        email_data["subject"],
        email_data["body"]
    )

    return results

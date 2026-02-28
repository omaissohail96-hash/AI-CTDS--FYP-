import os
import sys

# -------------------------------------------------
# Add project root to Python path (IMPORTANT)
# -------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(PROJECT_ROOT)

# -------------------------------------------------
# Import web detector
# -------------------------------------------------
from detectors.web_detector import predict_web_attack


# -------------------------------------------------
# Sample website feature input
# (Structure must match training features)
# -------------------------------------------------
sample_website_features = {
    "having_IP": 0,
    "URL_Length": 1,
    "Shortining_Service": 0,
    "having_At_Symbol": 1,
    "double_slash_redirecting": 1,
    "Prefix_Suffix": 1,
    "having_Sub_Domain": 1,
    "SSLfinal_State": 0,
    "Domain_registeration_length": 0,
    "Favicon": 1,
    "port": 0,
    "HTTPS_token": 1,
    "Request_URL": 1,
    "URL_of_Anchor": 0,
    "Links_in_tags": 1,
    "SFH": 1,
    "Submitting_to_email": 1,
    "Abnormal_URL": 1,
    "Redirect": 0,
    "on_mouseover": 1,
    "RightClick": 1,
    "popUpWidnow": 1,
    "Iframe": 1,
    "age_of_domain": 0,
    "DNSRecord": 0,
    "web_traffic": 0,
    "Page_Rank": 0,
    "Google_Index": 0,
    "Links_pointing_to_page": 1,
    "Statistical_report": 1
}

# -------------------------------------------------
# Prediction
# -------------------------------------------------
result = predict_web_attack(sample_website_features)

print("Attack Type :", result["attack_type"])
print("Confidence  :", result["confidence"], "%")
print("Severity    :", result["severity"])

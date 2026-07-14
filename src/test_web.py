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
# Sample web payload input.
# The trained TF-IDF payload model must be available before this script is run.
# -------------------------------------------------
sample_web_payload = "GET /products?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1"

# -------------------------------------------------
# Prediction
# -------------------------------------------------
result = predict_web_attack(sample_web_payload)

print("Attack Type :", result["attack_type"])
print("Confidence  :", result["confidence"], "%")
print("Severity    :", result["severity"])

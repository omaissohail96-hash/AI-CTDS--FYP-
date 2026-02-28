import os
import sys

# -------------------------------------------------
# Add project root to Python path (IMPORTANT)
# -------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(PROJECT_ROOT)


from detectors.email_detector import predict_email

# ---------- TEST EMAIL ----------
subject = "Urgent: Account Verification Required"
body = """
Dear user,
Your account has been suspended. Click the link below to verify:
farooqstudysphere@gmail.com
"""

result, confidence = predict_email(subject, body)

print("Prediction:", result)
print("Confidence:", confidence, "%")

"""Compatibility interface for the trained web-payload detector.

The legacy feature-vector phishing classifier is deliberately no longer used by
the web-attack module because it was incompatible with raw HTTP payload input.
"""

from detectors.web_detector_ml import predict_web_attack_ml


def predict_web_attack(payload: str):
    return predict_web_attack_ml(payload)

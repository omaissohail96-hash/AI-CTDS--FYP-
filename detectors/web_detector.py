import joblib
import pandas as pd

_model = None
_features = None

def _load():
    global _model, _features
    if _model is None:
        _model = joblib.load("models/web_attack_model.pkl")
        _features = joblib.load("models/web_attack_features.pkl")

LABEL_MAP = {
    0: "LEGITIMATE WEBSITE",
    1: "PHISHING WEBSITE"
}

SEVERITY_MAP = {
    "LEGITIMATE WEBSITE": "LOW",
    "PHISHING WEBSITE": "HIGH"
}

def predict_web_attack(feature_dict: dict):
    _load()

    # Ensure all features exist
    for col in _features:
        feature_dict.setdefault(col, 0)

    df = pd.DataFrame([feature_dict])[_features]

    pred = _model.predict(df)[0]
    confidence = _model.predict_proba(df)[0].max()

    label = LABEL_MAP[pred]

    return {
        "attack_type": label,
        "confidence": round(confidence * 100, 2),
        "severity": SEVERITY_MAP[label]
    }

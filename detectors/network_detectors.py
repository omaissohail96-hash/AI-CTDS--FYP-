import joblib
import pandas as pd

_model = None
_features = None
_scaler = None

def _load():
    global _model, _features, _scaler
    if _model is None:
        _model = joblib.load("models/network_ids_model.pkl")
        _features = joblib.load("models/network_features.pkl")
        _scaler = joblib.load("models/network_scaler.pkl")

LABEL_MAP = {
    0: "NORMAL TRAFFIC",
    1: "DoS ATTACK",
    2: "PORT SCAN",
    3: "BRUTE FORCE",
    4: "BOTNET"
}

def predict_network_attacks(flow_features: dict):
    _load()

    # Ensure all required features exist
    for col in _features:
        flow_features.setdefault(col, 0)

    df = pd.DataFrame([flow_features])[_features]
    df_scaled = _scaler.transform(df)

    pred = _model.predict(df_scaled)[0]
    confidence = _model.predict_proba(df_scaled)[0].max()

    label = LABEL_MAP.get(pred, "UNKNOWN")
    severity = "HIGH" if pred != 0 else "LOW"

    return {
        "attack_type": label,
        "confidence": round(confidence * 100, 2),
        "severity": severity
    }


def predict_network(flow_features: dict):
    result = predict_network_attacks(flow_features)
    return result["attack_type"], result["confidence"]


# Backward-compatible alias used by existing tests and scripts
predict_network_model = predict_network

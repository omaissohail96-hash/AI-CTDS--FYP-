import joblib
import re
import warnings
from sklearn.exceptions import InconsistentVersionWarning

warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

_model = None
_vectorizer = None

def _load():
    global _model, _vectorizer
    if _model is None:
        _model = joblib.load("models/email_phishing_model.pkl")
        _vectorizer = joblib.load("models/email_vectorizer.pkl")

def clean_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"http\S+", " URL ", text)
    text = re.sub(r"\W+", " ", text)
    return text.strip()

def predict_email_attack(subject: str, body: str):
    _load()

    full_text = f"{subject} {body}"
    cleaned = clean_text(full_text)

    X = _vectorizer.transform([cleaned])
    pred = _model.predict(X)[0]
    confidence = _model.predict_proba(X)[0].max()

    label = "PHISHING EMAIL" if pred == 1 else "LEGITIMATE EMAIL"
    severity = "HIGH" if pred == 1 else "LOW"

    return {
        "attack_type": label,
        "confidence": round(confidence * 100, 2),
        "severity": severity
    }

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

MODEL_PATH = "models/web_attack_model.pkl"
VECTORIZER_PATH = "models/web_attack_vectorizer.pkl"

_model = None
_vectorizer = None

# Mock dataset for training if model doesn't exist
MOCK_DATA = [
    # Normal
    {"payload": "GET / HTTP/1.1", "label": "NORMAL"},
    {"payload": "GET /index.html HTTP/1.1", "label": "NORMAL"},
    {"payload": "POST /login user=admin&pass=123", "label": "NORMAL"},
    {"payload": "GET /api/v1/health HTTP/1.1", "label": "NORMAL"},
    {"payload": "User-Agent: Mozilla/5.0", "label": "NORMAL"},
    
    # SQLi
    {"payload": "' OR 1=1 --", "label": "SQL INJECTION"},
    {"payload": "admin' --", "label": "SQL INJECTION"},
    {"payload": "1; DROP TABLE users", "label": "SQL INJECTION"},
    {"payload": "UNION SELECT username, password FROM users", "label": "SQL INJECTION"},
    {"payload": "1' OR '1'='1", "label": "SQL INJECTION"},
    
    # XSS
    {"payload": "<script>alert(1)</script>", "label": "CROSS-SITE SCRIPTING (XSS)"},
    {"payload": "<img src=x onerror=alert(1)>", "label": "CROSS-SITE SCRIPTING (XSS)"},
    {"payload": "javascript:alert('XSS')", "label": "CROSS-SITE SCRIPTING (XSS)"},
    {"payload": "onload=alert(1)", "label": "CROSS-SITE SCRIPTING (XSS)"},
    
    # LFI / Directory Traversal
    {"payload": "../../../../etc/passwd", "label": "PATH TRAVERSAL"},
    {"payload": "..\\..\\windows\\system32\\cmd.exe", "label": "PATH TRAVERSAL"},
    {"payload": "/etc/shadow", "label": "PATH TRAVERSAL"},
    
    # Command Injection
    {"payload": "; cat /etc/passwd", "label": "COMMAND INJECTION"},
    {"payload": "| ping -c 4 127.0.0.1", "label": "COMMAND INJECTION"},
    {"payload": "`whoami`", "label": "COMMAND INJECTION"}
]

def train_mock_model():
    """Trains a mock model if the user hasn't provided a large dataset."""
    os.makedirs("models", exist_ok=True)
    
    df = pd.DataFrame(MOCK_DATA)
    X_raw = df["payload"]
    y = df["label"]
    
    vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4), max_features=1000)
    X = vectorizer.fit_transform(X_raw)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print("Mock Web Attack ML model trained and saved.")

def _load():
    global _model, _vectorizer
    if _model is None or _vectorizer is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            train_mock_model()
            
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)

def predict_web_attack_ml(payload: str):
    _load()
    
    X = _vectorizer.transform([payload])
    
    pred_label = _model.predict(X)[0]
    pred_probs = _model.predict_proba(X)[0]
    confidence = float(np.max(pred_probs))
    
    # Extract important features for explanation
    feature_names = _vectorizer.get_feature_names_out()
    tfidf_scores = X.toarray()[0]
    
    # Get top 3 N-gram matches that contributed to the vector
    top_indices = np.argsort(tfidf_scores)[-3:][::-1]
    important_features = [
        feature_names[i] for i in top_indices if tfidf_scores[i] > 0
    ]
    
    severity = "SECURE"
    if pred_label != "NORMAL":
        severity = "CRITICAL" if confidence > 0.8 else "HIGH"
        
    return {
        "prediction": "MALICIOUS" if pred_label != "NORMAL" else "SAFE",
        "attack_type": pred_label if pred_label != "NORMAL" else "LEGITIMATE REQUEST",
        "confidence": round(confidence * 100, 2),
        "severity": severity,
        "important_features": important_features,
        "explanation": f"Model detected {pred_label} with {confidence*100:.1f}% confidence. Key features: {', '.join(important_features)}"
    }

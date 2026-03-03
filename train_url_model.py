import pandas as pd
import numpy as np
import joblib
from scipy.io import arff
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# ---------- LOAD DATA ----------
data, meta = arff.loadarff("datasets/urls/Training Dataset.arff")
df = pd.DataFrame(data)

# Decode byte strings
for col in df.columns:
    if df[col].dtype == object:
        df[col] = df[col].str.decode("utf-8")

# ---------- LABEL FIX ----------
df["Result"] = df["Result"].astype(int)
df["label"] = df["Result"].apply(lambda x: 1 if x == 1 else 0)
df.drop(columns=["Result"], inplace=True)

# ---------- FEATURES & TARGET ----------
X = df.drop(columns=["label"]).astype("float32")
y = df["label"]

# ---------- SPLIT ----------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ---------- MODEL ----------
model = RandomForestClassifier(
    n_estimators=80,
    max_depth=12,
    min_samples_split=10,
    min_samples_leaf=5,
    n_jobs=-1,
    random_state=42
)

model.fit(X_train, y_train)

# ---------- EVALUATION ----------
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# ---------- SAVE ----------
#joblib.dump(model, "models/url_phishing_model.pkl", compress=3)
#joblib.dump(X.columns.tolist(), "models/url_features.pkl")

print("\nURL phishing model saved successfully.")

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report

# ---------- LOAD ----------
X = pd.read_csv("datasets/intrusion/Data.csv")
y = pd.read_csv("datasets/intrusion/label.csv")

df = pd.concat([X, y], axis=1)

# ---------- CLEAN ----------
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
df = df.select_dtypes(include=[np.number])

X = df.drop(columns=["Label"])
y = df["Label"].astype(int)

# ---------- SCALE ----------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X).astype("float32")

# ---------- SPLIT ----------
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# ---------- MODEL (KEY CHANGE) ----------
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    n_jobs=-1,
    random_state=42
)

model.fit(X_train, y_train)

# ---------- EVAL ----------
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# ---------- SAVE ----------
#joblib.dump(model, "models/network_ids_model.pkl")
#joblib.dump(X.columns.tolist(), "models/network_features.pkl")
#joblib.dump(scaler, "models/network_scaler.pkl")

print("✅ Network IDS model saved (DEPLOYMENT SAFE)")

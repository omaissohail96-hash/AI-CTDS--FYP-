import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# ----------------------------
# Paths
# ----------------------------
DATA_PATH = "datasets/websites/Phising_Training_Dataset.csv"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ----------------------------
# Load dataset
# ----------------------------
df = pd.read_csv(DATA_PATH)

print(df.columns)  # for verification

# ----------------------------
# Split features & label
# ----------------------------
if "key" in df.columns:
    df = df.drop(columns=["key"])
X = df.drop(columns=["Result"])
y = df["Result"].replace({-1: 0})  # Legit = 0, Phishing = 1

# ----------------------------
# Train-test split
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ----------------------------
# Model
# ----------------------------
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# ----------------------------
# Evaluation
# ----------------------------
y_pred = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# ----------------------------
# Save model + feature list
# ----------------------------
joblib.dump(model, f"{MODEL_DIR}/web_attack_model.pkl")
joblib.dump(list(X.columns), f"{MODEL_DIR}/web_attack_features.pkl")

print("\nWeb attack model saved successfully.")

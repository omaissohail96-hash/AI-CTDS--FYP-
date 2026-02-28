# ==========================================
# Merge Multiple Email Datasets & Train Model
# ==========================================

import pandas as pd
import re
import joblib
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ---------- CONFIG ----------
DATASET_DIR = Path("datasets/emails")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)


# ---------- TEXT CLEANING ----------
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'http\S+', '', text)
    text = re.sub(r'\W+', ' ', text)
    return text


# ---------- LOAD & STANDARDIZE ONE DATASET ----------
def load_email_dataset(csv_path):
    df = pd.read_csv(csv_path, low_memory=False)
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]

    # Create text column safely
    subject = df['subject'] if 'subject' in df.columns else ''
    body = df['body'] if 'body' in df.columns else df.iloc[:, 0]

    df['text'] = subject.fillna('') + " " + body.fillna('')

    # Convert labels safely to numeric
    df['label'] = pd.to_numeric(df['label'], errors='coerce')
    df = df[df['label'].isin([0, 1])]
    df['label'] = df['label'].astype(int)

    df['text'] = df['text'].apply(clean_text)

    return df[['text', 'label']]


# ---------- LOAD ALL DATASETS ----------
all_dfs = []

for file in DATASET_DIR.glob("*.csv"):
    try:
        print(f"Loading: {file.name}")
        temp_df = load_email_dataset(file)
        print(f"  Rows loaded: {len(temp_df)}")
        all_dfs.append(temp_df)
    except Exception as e:
        print(f"  Skipped {file.name} بسبب error:", e)

# Merge everything
final_df = pd.concat(all_dfs, ignore_index=True)

print("\nFinal merged dataset shape:", final_df.shape)
print(final_df['label'].value_counts())


# 🔹 STEP 1: SAMPLE DATA (VERY IMPORTANT)
MAX_SAMPLES = 40000  # safe limit for student laptops

if len(final_df) > MAX_SAMPLES:
    final_df = (
        final_df
        .groupby('label', group_keys=False)
        .apply(lambda x: x.sample(
            n=int(MAX_SAMPLES * len(x) / len(final_df)),
            random_state=42
        ))
    )

print("Dataset used for training:", final_df.shape)
print(final_df['label'].value_counts())

# 🔹 STEP 2: TRAIN-TEST SPLIT
X_train, X_test, y_train, y_test = train_test_split(
    final_df['text'],
    final_df['label'],
    test_size=0.2,
    random_state=42,
    stratify=final_df['label']
)

# 🔹 STEP 3: TF-IDF (REDUCED + OPTIMIZED)
vectorizer = TfidfVectorizer(
    max_features=1000,          # reduced
    stop_words='english',
    dtype=np.float32,           # saves memory
    min_df=3
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# 🔹 STEP 4: MODEL
model = MultinomialNB()
model.fit(X_train_tfidf, y_train)

# 🔹 STEP 5: EVALUATION
y_pred = model.predict(X_test_tfidf)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))


# ---------- SAVE ----------
joblib.dump(model, MODEL_DIR / "email_phishing_model_v2.pkl")
joblib.dump(vectorizer, MODEL_DIR / "email_vectorizer_v2.pkl")

print("\nMerged model and vectorizer saved successfully.")

# ==============================
# Email Phishing Detection Model
# ==============================

import pandas as pd
import re
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ---------- STEP 1: LOAD DATASET ----------
# Load CSV safely (large file + mixed types)
df = pd.read_csv(
    r'C:\Users\Farooq\Desktop\Final_Year_Project\datasets\emails\SpamAssasin.csv',
    low_memory=False
)

# ---------- STEP 2: REMOVE UNUSED COLUMNS ----------
# Remove empty / unnamed columns
df = df.loc[:, ~df.columns.str.contains('^Unnamed')]

# ---------- STEP 3: CREATE TEXT FEATURE ----------
# Combine subject + body into one text column
df['text'] = df['subject'].fillna('') + " " + df['body'].fillna('')

# ---------- STEP 4: CLEAN LABEL COLUMN ----------

# Convert label column to numeric safely
df['label'] = pd.to_numeric(df['label'], errors='coerce')

# Keep only valid binary labels (0 and 1)
df = df[df['label'].isin([0, 1])]

# Convert to integer
df['label'] = df['label'].astype(int)



# ---------- STEP 5: BASIC TEXT CLEANING ----------
def clean_text(text):
    text = text.lower()
    text = re.sub(r'http\S+', '', text)       # remove URLs
    text = re.sub(r'\W+', ' ', text)          # remove special characters
    return text

df['text'] = df['text'].apply(clean_text)

# ---------- STEP 6: FEATURE EXTRACTION (TF-IDF) ----------
vectorizer = TfidfVectorizer(
    max_features=5000,
    stop_words='english'
)

X = vectorizer.fit_transform(df['text'])
y = df['label']

# ---------- STEP 7: TRAIN-TEST SPLIT ----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ---------- STEP 8: MODEL TRAINING ----------
model = MultinomialNB()
model.fit(X_train, y_train)

# ---------- STEP 9: MODEL EVALUATION ----------
y_pred = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# ---------- STEP 10: SAVE MODEL & VECTORIZER ----------
joblib.dump(model, "models/email_phishing_model.pkl")
joblib.dump(vectorizer, "models/email_vectorizer.pkl")

print("\nModel and vectorizer saved successfully.")
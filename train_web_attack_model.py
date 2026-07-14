"""Train reproducible CyberGuard web-attack payload classification artifacts.

Input CSV must contain a raw payload column and a label column.  The default
dataset path deliberately does not point to the phishing-website feature
dataset: that data is incompatible with payload text classification.
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from detectors.web_preprocessing import PREPROCESSING_VERSION, normalize_web_payload

ARTIFACT_VERSION = "1.0"
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "models"


def train_web_attack_model(
    data_path: Path,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    payload_column: str = "payload",
    label_column: str = "label",
    benign_label: str = "NORMAL",
    random_state: int = 42,
) -> dict:
    """Train and persist classifier, TF-IDF vectorizer and validation metadata."""
    if not data_path.is_file():
        raise FileNotFoundError(f"Web-attack training dataset was not found: {data_path}")

    frame = pd.read_csv(data_path)
    missing_columns = {payload_column, label_column}.difference(frame.columns)
    if missing_columns:
        raise ValueError(f"Training dataset is missing required columns: {sorted(missing_columns)}")

    frame = frame[[payload_column, label_column]].dropna()
    frame[payload_column] = frame[payload_column].astype(str).map(normalize_web_payload)
    frame[label_column] = frame[label_column].astype(str).str.strip()
    frame = frame[(frame[payload_column] != "") & (frame[label_column] != "")]
    class_counts = frame[label_column].value_counts()
    if len(class_counts) < 2:
        raise ValueError("Training dataset must contain at least two labels")
    if benign_label not in class_counts.index:
        raise ValueError(f"Configured benign label {benign_label!r} is absent from the training dataset")
    if class_counts.min() < 2:
        raise ValueError("Each class must contain at least two samples for a stratified train/test split")

    texts_train, texts_test, labels_train, labels_test = train_test_split(
        frame[payload_column], frame[label_column], test_size=0.20,
        random_state=random_state, stratify=frame[label_column],
    )
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=1, sublinear_tf=True)
    train_features = vectorizer.fit_transform(texts_train)
    test_features = vectorizer.transform(texts_test)
    classifier = LogisticRegression(
        max_iter=2000, random_state=random_state, class_weight="balanced",
    )
    classifier.fit(train_features, labels_train)
    predictions = classifier.predict(test_features)
    accuracy = float(accuracy_score(labels_test, predictions))

    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "web_attack_model.pkl"
    vectorizer_path = output_dir / "web_attack_vectorizer.pkl"
    metadata_path = output_dir / "web_attack_metadata.json"
    joblib.dump(classifier, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    metadata = {
        "artifact_version": ARTIFACT_VERSION,
        "preprocessing_version": PREPROCESSING_VERSION,
        "model_type": type(classifier).__name__,
        "vectorizer_type": "TfidfVectorizer",
        "feature_count": int(len(vectorizer.get_feature_names_out())),
        "classes": [str(label) for label in classifier.classes_],
        "benign_label": benign_label,
        "training_rows": int(len(frame)),
        "training_dataset": str(data_path),
        "random_state": random_state,
        "test_accuracy": accuracy,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return {
        "accuracy": accuracy,
        "classification_report": classification_report(labels_test, predictions, zero_division=0),
        "model_path": model_path,
        "vectorizer_path": vectorizer_path,
        "metadata_path": metadata_path,
        "metadata": metadata,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train CyberGuard's web-attack payload classifier")
    parser.add_argument("--data", required=True, type=Path, help="CSV containing payload and label columns")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, type=Path)
    parser.add_argument("--payload-column", default="payload")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--benign-label", default="NORMAL")
    args = parser.parse_args()
    result = train_web_attack_model(
        args.data, args.output_dir, args.payload_column, args.label_column, args.benign_label,
    )
    print(f"Test accuracy: {result['accuracy']:.4f}")
    print(result["classification_report"])
    print(f"Saved trained classifier: {result['model_path']}")
    print(f"Saved trained vectorizer: {result['vectorizer_path']}")
    print(f"Saved model metadata: {result['metadata_path']}")


if __name__ == "__main__":
    main()

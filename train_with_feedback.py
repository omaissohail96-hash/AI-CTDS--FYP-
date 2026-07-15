"""Offline-only web-attack model retraining with approved analyst feedback.

This program is deliberately not imported by the API.  An administrator runs
it, reviews the generated artifacts, and publishes them manually.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

from detectors.web_preprocessing import normalize_web_payload


def retrain(original: Path, feedback: Path, output_dir: Path) -> dict:
    original_data = pd.read_csv(original)[["payload", "label"]].rename(columns={"payload": "original_input", "label": "correct_label"})
    feedback_data = pd.read_csv(feedback)
    feedback_data = feedback_data[feedback_data["entity_type"] == "web"][["original_input", "correct_label"]]
    data = pd.concat([original_data, feedback_data], ignore_index=True).dropna()
    data["original_input"] = data["original_input"].astype(str).map(normalize_web_payload)
    data["correct_label"] = data["correct_label"].astype(str).str.strip()
    data = data[(data.original_input != "") & (data.correct_label != "")].drop_duplicates()
    if data.correct_label.nunique() < 2 or data.correct_label.value_counts().min() < 2:
        raise ValueError("Merged dataset needs two labels with at least two samples each")
    train_x, test_x, train_y, test_y = train_test_split(data.original_input, data.correct_label, test_size=.2, random_state=42, stratify=data.correct_label)
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)
    model = LogisticRegression(max_iter=2000, random_state=42, class_weight="balanced")
    model.fit(vectorizer.fit_transform(train_x), train_y)
    predicted = model.predict(vectorizer.transform(test_x))
    precision, recall, f1, _ = precision_recall_fscore_support(test_y, predicted, average="weighted", zero_division=0)
    timestamp = datetime.now(timezone.utc)
    version = timestamp.strftime("feedback-%Y%m%dT%H%M%SZ")
    version_dir = output_dir / version
    version_dir.mkdir(parents=True, exist_ok=False)
    joblib.dump(model, version_dir / "web_attack_model.pkl")
    joblib.dump(vectorizer, version_dir / "web_attack_vectorizer.pkl")
    metadata = {"model_version": version, "training_date": timestamp.isoformat(), "dataset_size": len(data),
                "feedback_samples": len(feedback_data), "accuracy": accuracy_score(test_y, predicted),
                "precision": precision, "recall": recall, "f1_score": f1, "source_dataset": str(original)}
    (version_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Offline retraining from approved CyberGuard feedback")
    parser.add_argument("--original-dataset", required=True, type=Path, help="CSV with payload,label columns")
    parser.add_argument("--feedback-dataset", default=Path("datasets/feedback_dataset.csv"), type=Path)
    parser.add_argument("--output-dir", default=Path("models/versions"), type=Path)
    args = parser.parse_args()
    print(json.dumps(retrain(args.original_dataset, args.feedback_dataset, args.output_dir), indent=2))

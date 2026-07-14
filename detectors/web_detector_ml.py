"""Strict inference loader for the trained web-attack payload classifier.

This module never trains or synthesizes a model.  Production inference requires
the artifacts produced by ``train_web_attack_model.py``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from scipy.sparse import spmatrix

from detectors.web_preprocessing import PREPROCESSING_VERSION, normalize_web_payload

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_PATH = MODEL_DIR / "web_attack_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "web_attack_vectorizer.pkl"
METADATA_PATH = MODEL_DIR / "web_attack_metadata.json"
ARTIFACT_VERSION = "1.0"


class WebAttackModelLoadError(RuntimeError):
    """Raised when required trained web-attack artifacts are absent or invalid."""


@dataclass(frozen=True)
class LoadedWebAttackModel:
    classifier: Any
    vectorizer: Any
    metadata: dict[str, Any]


_loaded_model: LoadedWebAttackModel | None = None


def _required_paths() -> tuple[Path, Path, Path]:
    return MODEL_PATH, VECTORIZER_PATH, METADATA_PATH


def reset_model_cache() -> None:
    """Clear in-process cache. Intended for test isolation only."""
    global _loaded_model
    _loaded_model = None


def _raise_invalid(reason: str) -> None:
    logger.critical("Web attack model validation failed: %s", reason)
    raise WebAttackModelLoadError(
        f"Web attack model is unavailable: {reason}. "
        "Run train_web_attack_model.py with a labelled web-payload dataset before starting CyberGuard."
    )


def _validate_loaded_artifacts(classifier: Any, vectorizer: Any, metadata: dict[str, Any]) -> None:
    missing_methods = []
    if not hasattr(classifier, "predict"):
        missing_methods.append("classifier.predict")
    if not hasattr(vectorizer, "transform"):
        missing_methods.append("vectorizer.transform")
    if missing_methods:
        _raise_invalid(f"artifact API mismatch: {', '.join(missing_methods)}")
    if not hasattr(classifier, "predict_proba"):
        _raise_invalid("classifier does not support predict_proba")
    if not hasattr(classifier, "classes_") or len(classifier.classes_) < 2:
        _raise_invalid("classifier must contain at least two trained classes")
    if not hasattr(vectorizer, "get_feature_names_out") or not hasattr(vectorizer, "vocabulary_"):
        _raise_invalid("vectorizer is not a fitted TF-IDF-compatible vectorizer")

    expected_dimension = int(metadata.get("feature_count", 0))
    vectorizer_dimension = len(vectorizer.get_feature_names_out())
    classifier_dimension = getattr(classifier, "n_features_in_", None)
    if expected_dimension <= 0:
        _raise_invalid("metadata feature_count is missing or invalid")
    if vectorizer_dimension != expected_dimension:
        _raise_invalid(
            f"vectorizer vocabulary dimension ({vectorizer_dimension}) does not match metadata ({expected_dimension})"
        )
    if classifier_dimension is not None and int(classifier_dimension) != vectorizer_dimension:
        _raise_invalid(
            f"classifier feature dimension ({classifier_dimension}) does not match vectorizer ({vectorizer_dimension})"
        )
    if metadata.get("artifact_version") != ARTIFACT_VERSION:
        _raise_invalid(f"unsupported artifact version {metadata.get('artifact_version')!r}")
    if metadata.get("preprocessing_version") != PREPROCESSING_VERSION:
        _raise_invalid("artifact preprocessing version does not match inference preprocessing")
    if set(map(str, classifier.classes_)) != set(map(str, metadata.get("classes", []))):
        _raise_invalid("classifier labels do not match metadata classes")


def load_web_attack_model(force_reload: bool = False) -> LoadedWebAttackModel:
    """Load and validate the trained classifier, vectorizer and metadata exactly once."""
    global _loaded_model
    if _loaded_model is not None and not force_reload:
        return _loaded_model

    missing = [str(path) for path in _required_paths() if not path.is_file()]
    if missing:
        _raise_invalid("missing required artifact(s): " + ", ".join(missing))

    try:
        classifier = joblib.load(MODEL_PATH)
    except Exception as exc:
        _raise_invalid(f"could not load classifier {MODEL_PATH}: {exc}")
    try:
        vectorizer = joblib.load(VECTORIZER_PATH)
    except Exception as exc:
        _raise_invalid(f"could not load vectorizer {VECTORIZER_PATH}: {exc}")
    try:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        _raise_invalid(f"could not load metadata {METADATA_PATH}: {exc}")

    _validate_loaded_artifacts(classifier, vectorizer, metadata)
    _loaded_model = LoadedWebAttackModel(classifier, vectorizer, metadata)
    logger.info(
        "Loaded trained web attack model version=%s features=%s classes=%s",
        metadata["artifact_version"], metadata["feature_count"], metadata["classes"],
    )
    return _loaded_model


def validate_web_attack_model() -> None:
    """Eager startup validation entry point; raises a clear error when invalid."""
    load_web_attack_model()


def predict_web_attack_ml(payload: str) -> dict[str, Any]:
    """Classify one payload using only the validated trained ML artifacts."""
    if not isinstance(payload, str) or not payload.strip():
        raise ValueError("Web attack payload must be a non-empty string")

    artifacts = load_web_attack_model()
    normalized_payload = normalize_web_payload(payload)
    features = artifacts.vectorizer.transform([normalized_payload])
    if not isinstance(features, spmatrix) or features.shape[1] != artifacts.metadata["feature_count"]:
        _raise_invalid("inference feature matrix does not match trained feature dimension")

    probabilities = np.asarray(artifacts.classifier.predict_proba(features)[0], dtype=float)
    if probabilities.shape[0] != len(artifacts.classifier.classes_) or not np.isfinite(probabilities).all():
        _raise_invalid("classifier returned invalid probability output")
    if not np.isclose(probabilities.sum(), 1.0, atol=1e-6):
        _raise_invalid("classifier probability output does not sum to 1")

    predicted_index = int(np.argmax(probabilities))
    predicted_label = str(artifacts.classifier.classes_[predicted_index])
    confidence = float(probabilities[predicted_index])
    benign_label = str(artifacts.metadata["benign_label"])

    feature_names = artifacts.vectorizer.get_feature_names_out()
    scores = features.toarray()[0]
    top_indices = np.argsort(scores)[-3:][::-1]
    important_features = [feature_names[index] for index in top_indices if scores[index] > 0]
    is_malicious = predicted_label != benign_label

    return {
        "prediction": "MALICIOUS" if is_malicious else "SAFE",
        "attack_type": predicted_label if is_malicious else "LEGITIMATE REQUEST",
        "confidence": round(confidence * 100, 2),
        "severity": "CRITICAL" if is_malicious and confidence >= 0.80 else "HIGH" if is_malicious else "SECURE",
        "important_features": important_features,
        "explanation": (
            f"Trained model predicted {predicted_label} with {confidence * 100:.1f}% confidence. "
            f"Top TF-IDF features: {', '.join(important_features) or 'none'}"
        ),
        "model_version": artifacts.metadata["artifact_version"],
    }

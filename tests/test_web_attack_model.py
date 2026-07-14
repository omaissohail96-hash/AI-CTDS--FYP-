from __future__ import annotations

import json

import pandas as pd
import pytest

from detectors import web_detector_ml as detector
from train_web_attack_model import train_web_attack_model


@pytest.fixture()
def trained_artifact_directory(tmp_path, monkeypatch):
    training_rows = []
    examples = {
        "NORMAL": [
            "GET / HTTP/1.1", "GET /products?page=2 HTTP/1.1",
            "POST /login username=alice HTTP/1.1", "GET /assets/site.css HTTP/1.1",
            "GET /api/v1/health HTTP/1.1", "POST /profile name=Alice HTTP/1.1",
        ],
        "SQL INJECTION": [
            "GET /users?id=1 UNION SELECT password FROM users", "GET /?id=1 OR 1=1 --",
            "POST /login username=admin' --", "GET /search?q=' OR '1'='1",
            "GET /orders?id=1; DROP TABLE orders", "GET /?q=benchmark(1000000,md5(1))",
        ],
        "CROSS-SITE SCRIPTING (XSS)": [
            "GET /?q=<script>alert(1)</script>", "POST /comment text=<img src=x onerror=alert(1)>",
            "GET /?next=javascript:alert(1)", "GET /?name=<svg onload=alert(1)>",
            "POST /bio value=<script>confirm(1)</script>", "GET /?x=<body onload=alert(1)>",
        ],
    }
    for label, payloads in examples.items():
        for payload in payloads:
            training_rows.extend({"payload": payload, "label": label} for _ in range(3))

    dataset_path = tmp_path / "web_payloads.csv"
    pd.DataFrame(training_rows).to_csv(dataset_path, index=False)
    train_web_attack_model(dataset_path, tmp_path)

    monkeypatch.setattr(detector, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(detector, "MODEL_PATH", tmp_path / "web_attack_model.pkl")
    monkeypatch.setattr(detector, "VECTORIZER_PATH", tmp_path / "web_attack_vectorizer.pkl")
    monkeypatch.setattr(detector, "METADATA_PATH", tmp_path / "web_attack_metadata.json")
    detector.reset_model_cache()
    yield tmp_path
    detector.reset_model_cache()


def test_trained_artifacts_load_and_match_metadata(trained_artifact_directory):
    artifacts = detector.load_web_attack_model()
    assert artifacts.metadata["feature_count"] == len(artifacts.vectorizer.get_feature_names_out())
    assert artifacts.classifier.n_features_in_ == artifacts.metadata["feature_count"]
    assert set(artifacts.classifier.classes_) == set(artifacts.metadata["classes"])


def test_malicious_and_benign_predictions_use_model_probabilities(trained_artifact_directory):
    malicious = detector.predict_web_attack_ml("GET /?id=1 UNION SELECT password FROM users HTTP/1.1")
    benign = detector.predict_web_attack_ml("GET /products?page=2 HTTP/1.1")
    assert malicious["prediction"] == "MALICIOUS"
    assert malicious["attack_type"] == "SQL INJECTION"
    assert benign["prediction"] == "SAFE"
    for result in (malicious, benign):
        assert 0.0 <= result["confidence"] <= 100.0
        assert result["model_version"] == "1.0"


def test_missing_artifacts_raise_clear_error(tmp_path, monkeypatch):
    monkeypatch.setattr(detector, "MODEL_PATH", tmp_path / "missing_model.pkl")
    monkeypatch.setattr(detector, "VECTORIZER_PATH", tmp_path / "missing_vectorizer.pkl")
    monkeypatch.setattr(detector, "METADATA_PATH", tmp_path / "missing_metadata.json")
    detector.reset_model_cache()
    with pytest.raises(detector.WebAttackModelLoadError, match="missing required artifact"):
        detector.load_web_attack_model()

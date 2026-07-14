"""Shared, versioned preprocessing for web-attack model training and inference."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote_plus

PREPROCESSING_VERSION = "web-payload-normalize-v1"


def normalize_web_payload(payload: str) -> str:
    """Apply the exact deterministic text normalization used by the training pipeline."""
    if not isinstance(payload, str):
        raise TypeError("Web attack payload must be a string")
    normalized = unicodedata.normalize("NFKC", payload)
    normalized = unquote_plus(normalized)
    normalized = normalized.lower()
    return re.sub(r"\s+", " ", normalized).strip()

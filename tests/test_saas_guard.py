from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from src.utils.saas_guard import SaaSGuard


def test_quota_error_contains_usage_and_monthly_reset():
    db = MagicMock()
    db.query.return_value.filter.return_value.count.return_value = 3
    workspace = SimpleNamespace(id="workspace-1", monthly_quota=3)

    with pytest.raises(HTTPException) as exc_info:
        SaaSGuard.check_quota(db, workspace)

    error = exc_info.value
    assert error.status_code == 429
    assert error.detail["code"] == "monthly_quota_exhausted"
    assert error.detail["usage"] == 3
    assert error.detail["limit"] == 3
    assert error.detail["reset_at"].endswith("Z")
    assert error.headers["X-RateLimit-Remaining"] == "0"


def test_rate_limit_error_contains_retry_after_and_reset_time():
    db = MagicMock()
    oldest_scan = SimpleNamespace(created_at=datetime.utcnow() - timedelta(seconds=15))
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [oldest_scan]
    workspace = SimpleNamespace(id="workspace-1", rate_limit_rpm=1)

    with pytest.raises(HTTPException) as exc_info:
        SaaSGuard.check_rate_limit(db, workspace)

    error = exc_info.value
    assert error.status_code == 429
    assert error.detail["code"] == "rate_limit_exceeded"
    assert 1 <= error.detail["retry_after_seconds"] <= 60
    assert error.headers["Retry-After"] == str(error.detail["retry_after_seconds"])


def test_rate_limit_handles_timezone_aware_postgres_timestamps():
    db = MagicMock()
    oldest_scan = SimpleNamespace(created_at=datetime.now(timezone.utc) - timedelta(seconds=15))
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [oldest_scan]
    workspace = SimpleNamespace(id="workspace-1", rate_limit_rpm=1)

    with pytest.raises(HTTPException) as exc_info:
        SaaSGuard.check_rate_limit(db, workspace)

    assert exc_info.value.detail["reset_at"].endswith("Z")
    assert "+00:00Z" not in exc_info.value.detail["reset_at"]

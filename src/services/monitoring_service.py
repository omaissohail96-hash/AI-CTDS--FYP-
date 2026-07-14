from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from src.core.database import SessionLocal
from src.models.models import Alert, ScanHistory, User
from src.utils.metrics_collector import metrics


class MonitoringService:
    @staticmethod
    def get_system_snapshot() -> Dict[str, Any]:
        db = SessionLocal()
        try:
            alert_count = db.query(Alert).count()
            scan_count = db.query(ScanHistory).count()
            user_count = db.query(User).count()
            recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(5).all()
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "metrics": metrics.get_metrics(),
                "counts": {
                    "alerts": alert_count,
                    "scans": scan_count,
                    "users": user_count,
                },
                "recent_alerts": [
                    {
                        "id": str(item.id),
                        "severity": item.severity,
                        "title": item.title,
                        "entity": item.entity,
                    }
                    for item in recent_alerts
                ],
            }
        finally:
            db.close()

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from math import radians, sin, cos, asin, sqrt
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import func
from sqlalchemy import and_
from sqlalchemy.orm import Session

from src.models.models import Alert, User, UserBehaviorEvent, UserBehaviorProfile
from src.services.alert_service import AlertSeverity, AlertService


class UserBehaviorAnalyticsService:
    """
    IDS-only User Behavior Analytics engine.
    Records behavior, maintains baselines, scores anomalies, and creates alerts
    without blocking users or changing account state.
    """

    ALERT_THRESHOLD = 61
    CRITICAL_THRESHOLD = 86
    PROFILE_WINDOW_DAYS = 30

    LOCATION_COORDINATES = {
        "karachi": (24.8607, 67.0011),
        "lahore": (31.5204, 74.3587),
        "islamabad": (33.6844, 73.0479),
        "london": (51.5072, -0.1276),
        "new york": (40.7128, -74.0060),
        "dubai": (25.2048, 55.2708),
        "singapore": (1.3521, 103.8198),
        "tokyo": (35.6762, 139.6503),
    }

    @classmethod
    def record_event(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
        event_type: str,
        ip_address: str | None = None,
        location: str | None = None,
        endpoint_accessed: str | None = None,
        timestamp: datetime | None = None,
        metadata: Optional[Dict[str, Any]] = None,
        commit: bool = True,
    ) -> UserBehaviorEvent:
        timestamp = timestamp or datetime.utcnow()
        location = location or cls._infer_location(ip_address)

        anomaly = cls.evaluate_event(
            db=db,
            workspace_id=workspace_id,
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            location=location,
            endpoint_accessed=endpoint_accessed,
            timestamp=timestamp,
            metadata=metadata or {},
        )

        event = UserBehaviorEvent(
            workspace_id=workspace_id,
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            location=location,
            endpoint_accessed=endpoint_accessed,
            timestamp=timestamp,
            anomaly_score=anomaly["score"],
            risk_level=anomaly["risk_level"],
            explanation={
                "explanation": anomaly["explanation"],
                "signals": anomaly["signals"],
                "recommended_action": anomaly["recommended_action"],
            },
        )
        db.add(event)
        db.flush()

        if user_id:
            cls.rebuild_profile(db, workspace_id, user_id)

        if anomaly["score"] >= cls.ALERT_THRESHOLD:
            cls._generate_uba_alert(
                db=db,
                workspace_id=workspace_id,
                user_id=user_id,
                event=event,
                anomaly=anomaly,
            )

        if commit:
            db.commit()
        return event

    @classmethod
    def evaluate_event(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
        event_type: str,
        ip_address: str | None,
        location: str | None,
        endpoint_accessed: str | None,
        timestamp: datetime,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        profile = cls.get_or_create_profile(db, workspace_id, user_id)
        signals: List[Dict[str, Any]] = []
        score = 0

        common_ips = set(profile.common_ip_addresses or [])
        common_locations = {str(item).lower() for item in (profile.common_locations or [])}
        common_hours = set(int(hour) for hour in (profile.common_login_hours or []))

        if user_id and ip_address and common_ips and ip_address not in common_ips:
            signals.append({"type": "new_ip", "detail": f"New IP address {ip_address} observed for this user.", "score": 20})
            score += 20

        if user_id and location and common_locations and location.lower() not in common_locations:
            signals.append({"type": "new_location", "detail": f"New location {location} differs from baseline locations.", "score": 25})
            score += 25

        if user_id and event_type in {"login_success", "dashboard_activity", "api_request", "api_key_usage"}:
            hour = timestamp.hour
            if common_hours and hour not in common_hours:
                signals.append({"type": "off_hours_activity", "detail": f"Activity at {hour}:00 is outside common login hours.", "score": 15})
                score += 15

        impossible_travel = cls._detect_impossible_travel(
            db, workspace_id, user_id, location, timestamp
        )
        if impossible_travel:
            signals.append(impossible_travel)
            score += impossible_travel["score"]

        api_spike = cls._detect_api_usage_spike(
            db, workspace_id, user_id, profile, event_type, timestamp
        )
        if api_spike:
            signals.append(api_spike)
            score += api_spike["score"]

        endpoint_signal = cls._detect_endpoint_anomaly(
            db, workspace_id, user_id, endpoint_accessed
        )
        if endpoint_signal:
            signals.append(endpoint_signal)
            score += endpoint_signal["score"]

        auth_fail_signal = cls._detect_auth_failure_chain(
            db, workspace_id, user_id, event_type, timestamp
        )
        if auth_fail_signal:
            signals.append(auth_fail_signal)
            score += auth_fail_signal["score"]

        if event_type == "login_failed":
            score += 10
            signals.append({"type": "failed_login", "detail": "Authentication failure recorded.", "score": 10})

        score = min(100, max(score, profile.baseline_risk_score or 0))
        risk_level = cls.risk_level(score)
        return {
            "score": score,
            "risk_level": risk_level,
            "signals": signals,
            "explanation": cls.explain_event(event_type, location, timestamp, signals, score),
            "recommended_action": cls.recommended_action(score, signals),
        }

    @classmethod
    def rebuild_profile(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
    ) -> UserBehaviorProfile:
        profile = cls.get_or_create_profile(db, workspace_id, user_id)
        if not user_id:
            return profile

        since = datetime.utcnow() - timedelta(days=cls.PROFILE_WINDOW_DAYS)
        events = db.query(UserBehaviorEvent).filter(
            UserBehaviorEvent.workspace_id == workspace_id,
            UserBehaviorEvent.user_id == user_id,
            UserBehaviorEvent.timestamp >= since,
        ).all()

        by_day = defaultdict(lambda: {"logins": 0, "api": 0})
        ip_counter = Counter()
        location_counter = Counter()
        hour_counter = Counter()
        risk_scores = []

        for event in events:
            day = event.timestamp.date().isoformat() if event.timestamp else "unknown"
            if event.event_type == "login_success":
                by_day[day]["logins"] += 1
                if event.timestamp:
                    hour_counter[event.timestamp.hour] += 1
            if event.event_type in {"api_request", "api_key_usage", "agent_analysis"}:
                by_day[day]["api"] += 1
            if event.ip_address:
                ip_counter[event.ip_address] += 1
            if event.location:
                location_counter[event.location] += 1
            risk_scores.append(event.anomaly_score or 0)

        active_days = max(len(by_day), 1)
        profile.average_daily_logins = round(sum(item["logins"] for item in by_day.values()) / active_days)
        profile.average_api_calls = round(sum(item["api"] for item in by_day.values()) / active_days)
        profile.common_ip_addresses = [item for item, _ in ip_counter.most_common(5)]
        profile.common_locations = [item for item, _ in location_counter.most_common(5)]
        profile.common_login_hours = [item for item, _ in hour_counter.most_common(8)]
        profile.baseline_risk_score = round(sum(risk_scores) / len(risk_scores)) if risk_scores else 0
        profile.updated_at = datetime.utcnow()
        db.flush()
        return profile

    @classmethod
    def get_or_create_profile(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
    ) -> UserBehaviorProfile:
        profile = db.query(UserBehaviorProfile).filter(
            UserBehaviorProfile.workspace_id == workspace_id,
            UserBehaviorProfile.user_id == user_id,
        ).first()
        if profile:
            return profile

        profile = UserBehaviorProfile(
            workspace_id=workspace_id,
            user_id=user_id,
            common_ip_addresses=[],
            common_locations=[],
            common_login_hours=[],
        )
        db.add(profile)
        db.flush()
        return profile

    @classmethod
    def workspace_stats(cls, db: Session, workspace_id: uuid.UUID) -> Dict[str, Any]:
        since = datetime.utcnow() - timedelta(days=7)
        profiles = db.query(UserBehaviorProfile).filter(
            UserBehaviorProfile.workspace_id == workspace_id
        ).all()
        events = db.query(UserBehaviorEvent).filter(
            UserBehaviorEvent.workspace_id == workspace_id,
            UserBehaviorEvent.timestamp >= since,
        ).all()

        risk_counts = Counter(event.risk_level for event in events)
        top_users = cls.top_anomalous_users(db, workspace_id, limit=5)
        return {
            "total_users_monitored": len({str(profile.user_id) for profile in profiles if profile.user_id}),
            "events_7d": len(events),
            "anomalies_7d": sum(1 for event in events if (event.anomaly_score or 0) >= cls.ALERT_THRESHOLD),
            "average_workspace_risk": round(sum(event.anomaly_score or 0 for event in events) / len(events), 2) if events else 0,
            "risk_distribution": [
                {"risk_level": level, "count": risk_counts.get(level, 0)}
                for level in ["NORMAL", "SUSPICIOUS", "HIGH", "CRITICAL"]
            ],
            "top_anomalous_users": top_users,
        }

    @classmethod
    def top_anomalous_users(cls, db: Session, workspace_id: uuid.UUID, limit: int = 10) -> List[Dict[str, Any]]:
        rows = db.query(
            UserBehaviorEvent.user_id,
            func.max(UserBehaviorEvent.anomaly_score),
            func.count(UserBehaviorEvent.id),
        ).filter(
            UserBehaviorEvent.workspace_id == workspace_id,
            UserBehaviorEvent.user_id.isnot(None),
        ).group_by(UserBehaviorEvent.user_id).order_by(func.max(UserBehaviorEvent.anomaly_score).desc()).limit(limit).all()

        users = {
            user.id: user for user in db.query(User).filter(User.workspace_id == workspace_id).all()
        }
        return [
            {
                "user_id": str(user_id),
                "email": users.get(user_id).email if users.get(user_id) else "Unknown user",
                "risk_score": int(max_score or 0),
                "risk_level": cls.risk_level(int(max_score or 0)),
                "event_count": event_count,
            }
            for user_id, max_score, event_count in rows
        ]

    @classmethod
    def user_detail(cls, db: Session, workspace_id: uuid.UUID, user_id: uuid.UUID) -> Dict[str, Any]:
        profile = cls.get_or_create_profile(db, workspace_id, user_id)
        events = db.query(UserBehaviorEvent).filter(
            UserBehaviorEvent.workspace_id == workspace_id,
            UserBehaviorEvent.user_id == user_id,
        ).order_by(UserBehaviorEvent.timestamp.desc()).limit(100).all()
        return {
            "profile": cls.serialize_profile(profile),
            "events": [cls.serialize_event(event) for event in events],
            "current_risk_score": max([event.anomaly_score or 0 for event in events], default=0),
        }

    @classmethod
    def serialize_event(cls, event: UserBehaviorEvent) -> Dict[str, Any]:
        return {
            "id": str(event.id),
            "workspace_id": str(event.workspace_id),
            "user_id": str(event.user_id) if event.user_id else None,
            "event_type": event.event_type,
            "ip_address": event.ip_address,
            "location": event.location,
            "endpoint_accessed": event.endpoint_accessed,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "anomaly_score": event.anomaly_score,
            "risk_level": event.risk_level,
            "explanation": event.explanation or {},
        }

    @classmethod
    def serialize_profile(cls, profile: UserBehaviorProfile) -> Dict[str, Any]:
        return {
            "id": str(profile.id),
            "workspace_id": str(profile.workspace_id),
            "user_id": str(profile.user_id) if profile.user_id else None,
            "average_daily_logins": profile.average_daily_logins,
            "average_api_calls": profile.average_api_calls,
            "common_ip_addresses": profile.common_ip_addresses or [],
            "common_locations": profile.common_locations or [],
            "common_login_hours": profile.common_login_hours or [],
            "baseline_risk_score": profile.baseline_risk_score,
            "created_at": profile.created_at.isoformat() if profile.created_at else None,
            "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
        }

    @staticmethod
    def risk_level(score: int) -> str:
        if score >= 86:
            return "CRITICAL"
        if score >= 61:
            return "HIGH"
        if score >= 31:
            return "SUSPICIOUS"
        return "NORMAL"

    @classmethod
    def explain_event(
        cls,
        event_type: str,
        location: str | None,
        timestamp: datetime,
        signals: List[Dict[str, Any]],
        score: int,
    ) -> str:
        if not signals:
            return f"{event_type.replace('_', ' ').title()} matched established behavior patterns with a UBA risk score of {score}."
        signal_text = "; ".join(signal["detail"] for signal in signals[:3])
        return (
            f"{event_type.replace('_', ' ').title()} received a UBA risk score of {score}. "
            f"Observed context: location={location or 'unknown'}, hour={timestamp.hour}. "
            f"Signals: {signal_text}."
        )

    @classmethod
    def recommended_action(cls, score: int, signals: List[Dict[str, Any]]) -> str:
        if score < cls.ALERT_THRESHOLD:
            return "Continue monitoring; no immediate analyst action required."
        if any(signal["type"] == "impossible_travel" for signal in signals):
            return "Verify user identity, review recent sessions, and investigate possible account takeover. Do not automatically block from IDS workflow."
        if any(signal["type"] == "api_usage_spike" for signal in signals):
            return "Review API keys, endpoint access patterns, and recent automation changes."
        if any(signal["type"] == "auth_failure_chain" for signal in signals):
            return "Review authentication logs and confirm the successful login was legitimate."
        return "Escalate to analyst review and correlate with recent IDS alerts, audit logs, and scan history."

    @classmethod
    def _detect_impossible_travel(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
        location: str | None,
        timestamp: datetime,
    ) -> Dict[str, Any] | None:
        if not user_id or not location:
            return None
        previous = db.query(UserBehaviorEvent).filter(
            UserBehaviorEvent.workspace_id == workspace_id,
            UserBehaviorEvent.user_id == user_id,
            UserBehaviorEvent.location.isnot(None),
            UserBehaviorEvent.timestamp < timestamp,
        ).order_by(UserBehaviorEvent.timestamp.desc()).first()
        if not previous or not previous.location or previous.location.lower() == location.lower():
            return None

        distance = cls._distance_km(previous.location, location)
        hours = max((timestamp - previous.timestamp).total_seconds() / 3600, 0.1)
        speed = distance / hours
        if distance >= 750 and speed > 900:
            return {
                "type": "impossible_travel",
                "detail": f"Travel from {previous.location} to {location} in {round(hours, 2)} hours implies {round(speed)} km/h.",
                "score": 55,
            }
        return None

    @classmethod
    def _detect_api_usage_spike(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
        profile: UserBehaviorProfile,
        event_type: str,
        timestamp: datetime,
    ) -> Dict[str, Any] | None:
        if event_type not in {"api_request", "api_key_usage", "agent_analysis"}:
            return None
        day_start = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        current_count = db.query(UserBehaviorEvent).filter(
            UserBehaviorEvent.workspace_id == workspace_id,
            UserBehaviorEvent.user_id == user_id,
            UserBehaviorEvent.event_type.in_(["api_request", "api_key_usage", "agent_analysis"]),
            UserBehaviorEvent.timestamp >= day_start,
        ).count() + 1
        baseline = max(profile.average_api_calls or 0, 20)
        if current_count >= baseline * 5:
            return {
                "type": "api_usage_spike",
                "detail": f"Daily API activity reached {current_count}, exceeding the baseline of {baseline}.",
                "score": 40,
            }
        return None

    @classmethod
    def _detect_endpoint_anomaly(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
        endpoint_accessed: str | None,
    ) -> Dict[str, Any] | None:
        if not user_id or not endpoint_accessed:
            return None
        seen = db.query(UserBehaviorEvent.id).filter(
            UserBehaviorEvent.workspace_id == workspace_id,
            UserBehaviorEvent.user_id == user_id,
            UserBehaviorEvent.endpoint_accessed == endpoint_accessed,
        ).first()
        sensitive = any(token in endpoint_accessed for token in ["/workspace", "/settings", "/api-keys", "/admin"])
        if not seen and sensitive:
            return {
                "type": "privilege_usage_anomaly",
                "detail": f"User accessed sensitive endpoint {endpoint_accessed} for the first time.",
                "score": 25,
            }
        return None

    @classmethod
    def _detect_auth_failure_chain(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
        event_type: str,
        timestamp: datetime,
    ) -> Dict[str, Any] | None:
        if event_type != "login_success" or not user_id:
            return None
        window = timestamp - timedelta(minutes=30)
        failures = db.query(UserBehaviorEvent).filter(
            UserBehaviorEvent.workspace_id == workspace_id,
            UserBehaviorEvent.user_id == user_id,
            UserBehaviorEvent.event_type == "login_failed",
            UserBehaviorEvent.timestamp >= window,
        ).count()
        if failures >= 3:
            return {
                "type": "auth_failure_chain",
                "detail": f"{failures} failed login attempts preceded this successful authentication.",
                "score": 35,
            }
        return None

    @classmethod
    def _generate_uba_alert(
        cls,
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID | None,
        event: UserBehaviorEvent,
        anomaly: Dict[str, Any],
    ) -> Alert | None:
        entity = str(user_id or event.ip_address or event.id)
        cooldown = datetime.utcnow() - timedelta(minutes=AlertService.DUPLICATE_ALERT_COOLDOWN)
        duplicate = db.query(Alert.id).filter(
            and_(
                Alert.workspace_id == workspace_id,
                Alert.entity == entity,
                Alert.alert_type == "user_behavior_anomaly",
                Alert.created_at > cooldown,
                Alert.resolved_status == False,
            )
        ).first()
        if duplicate:
            return None
        alert = Alert(
            workspace_id=workspace_id,
            user_id=user_id,
            alert_type="user_behavior_anomaly",
            severity=AlertSeverity.from_risk_score(anomaly["score"]),
            title="User Behavior Anomaly Detected",
            description=anomaly["explanation"],
            entity=entity,
            entity_type="user",
            source_vector="UBA",
            risk_score=anomaly["score"],
            ml_confidence=anomaly["score"],
            indicators=[
                {"type": signal["type"], "value": signal["detail"], "source": "uba"}
                for signal in anomaly["signals"]
            ],
            correlated_events=len(anomaly["signals"]),
            recommended_action=anomaly["recommended_action"],
            resolved_status=False,
        )
        db.add(alert)
        db.flush()
        return alert

    @classmethod
    def _infer_location(cls, ip_address: str | None) -> str | None:
        if not ip_address:
            return None
        if ip_address.startswith(("10.", "192.168.", "172.")) or ip_address in {"127.0.0.1", "::1"}:
            return "Internal Network"
        # Deterministic demo fallback for environments without a GeoIP database.
        last_octet = 0
        try:
            last_octet = int(ip_address.split(".")[-1])
        except (ValueError, AttributeError):
            return "Unknown"
        return ["Karachi", "Lahore", "London", "Dubai", "Singapore"][last_octet % 5]

    @classmethod
    def _distance_km(cls, source: str, destination: str) -> float:
        src = cls.LOCATION_COORDINATES.get(source.lower())
        dst = cls.LOCATION_COORDINATES.get(destination.lower())
        if not src or not dst:
            return 0
        lat1, lon1 = map(radians, src)
        lat2, lon2 = map(radians, dst)
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        value = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
        return 6371 * 2 * asin(sqrt(value))

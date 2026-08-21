from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Integer, JSON, Index, Float, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
import uuid

Base = declarative_base()


class Workspace(Base):
    __tablename__ = "workspaces"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    tier = Column(String, default="free")          # free, pro, enterprise
    monthly_quota = Column(Integer, default=100)   # Max scans per month
    rate_limit_rpm = Column(Integer, default=10)   # Requests per minute
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    role = Column(String, default="viewer")         # admin, developer, viewer
    is_active = Column(Boolean, default=True)
    # Token version for family-based refresh token revocation
    refresh_token_version = Column(Integer, default=0, nullable=False)
    # Login tracking
    last_login_ip = Column(String, nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    login_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class WorkspaceUser(Base):
    """Authoritative workspace membership and role assignment."""
    __tablename__ = "workspace_users"
    __table_args__ = (
        Index("uq_workspace_user_membership", "workspace_id", "user_id", unique=True),
        Index("ix_workspace_users_workspace_role", "workspace_id", "role"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    role = Column(String, nullable=False, default="viewer", index=True)
    status = Column(String, nullable=False, default="active", index=True)  # active | pending
    invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    joined_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class UserMFA(Base):
    __tablename__ = "user_mfa"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), unique=True, nullable=False)
    secret = Column(String, nullable=False)
    enabled = Column(Boolean, default=False)
    recovery_codes = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Role(Base):
    __tablename__ = "roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False) # e.g., scan:create
    description = Column(String)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    permission_id = Column(UUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False)

class RefreshToken(Base):
    """
    Tracks issued refresh tokens for rotation and explicit revocation.
    One row per active refresh token (old tokens are purged on rotation).
    """
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_token_user", "user_id"),
        Index("ix_refresh_token_hash", "token_hash"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)   # SHA-256 of raw token
    jti = Column(String, nullable=True, index=True)            # JWT ID from payload
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    user_agent = Column(String, nullable=True)
    client_ip = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class APIKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_key_workspace_active", "workspace_id", "is_active"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    key_hash = Column(String, unique=True, index=True, nullable=False)  # SHA-256, never plain text
    label = Column(String, nullable=False)
    # Human-readable details for the system that uses this credential.
    integration_name = Column(String, nullable=True)
    website_url = Column(String, nullable=True)
    # Automatically observed from browser Origin/Referer headers on API use.
    detected_website_url = Column(String, nullable=True)
    detected_at = Column(DateTime(timezone=True), nullable=True)
    # Owner-approved website monitoring. A detected Origin is never enabled
    # automatically; an administrator must explicitly approve this URL.
    website_monitoring_enabled = Column(Boolean, default=False, nullable=False)
    monitoring_interval_hours = Column(Integer, nullable=True)
    last_website_scan_at = Column(DateTime(timezone=True), nullable=True)
    next_website_scan_at = Column(DateTime(timezone=True), nullable=True)
    last_website_scan_verdict = Column(String, nullable=True)
    last_website_scan_score = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    # Expiration (None = non-expiring)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    # Usage analytics
    usage_count = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)
    last_used = Column(DateTime(timezone=True), nullable=True)
    last_used_ip = Column(String, nullable=True)
    # Rotation support – track when last rotated
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class APIKeyAuditLog(Base):
    """Per-request audit trail for API key usage (append-only)."""
    __tablename__ = "api_key_audit_logs"
    __table_args__ = (
        Index("ix_apikey_audit_key_time", "api_key_id", "created_at"),
        Index("ix_apikey_audit_workspace_time", "workspace_id", "created_at"),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    api_key_id = Column(String, nullable=False, index=True)   # stringified UUID
    workspace_id = Column(String, nullable=False, index=True)  # stringified UUID
    endpoint = Column(String)          # e.g. /api/v1/agent/analyze
    method = Column(String)            # GET, POST …
    status_code = Column(Integer)      # HTTP response code
    client_ip = Column(String)
    response_ms = Column(Float)        # round-trip ms
    event = Column(String)             # created | used | rotated | revoked
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incident_workspace_created", "workspace_id", "created_at"),
        Index("ix_incident_workspace_status", "workspace_id", "status"),
        Index("ix_incident_workspace_severity", "workspace_id", "severity"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    severity = Column(String, nullable=False, default="LOW")
    risk_score = Column(Integer, nullable=False, default=0)
    confidence = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    affected_users = Column(JSON, default=list)
    affected_ips = Column(JSON, default=list)
    affected_urls_domains = Column(JSON, default=list)
    affected_endpoints = Column(JSON, default=list)
    related_alerts = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    correlation_reasons = Column(JSON, default=list)
    status = Column(String, default="OPEN", index=True) # OPEN | INVESTIGATING | RESOLVED

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ScanHistory(Base):
    __tablename__ = "scan_history"
    __table_args__ = (
        Index("ix_scan_history_workspace_created", "workspace_id", "created_at"),
        Index("ix_scan_history_workspace_verdict", "workspace_id", "verdict"),
        Index("ix_scan_history_workspace_attack_type", "workspace_id", "attack_type"),
        Index("ix_scan_history_workspace_entity", "workspace_id", "entity"),
        Index("ix_scan_history_workspace_severity", "workspace_id", "severity"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    input_type = Column(String)        # url, email, network, web
    entity = Column(String, index=True)
    entities = Column(JSON, default=list)
    attack_type = Column(String, index=True)
    severity = Column(String, index=True)
    ml_confidence = Column(Integer, default=0)
    intelligence_hit = Column(Boolean, default=False)
    correlation_hit = Column(Boolean, default=False)
    prevention_triggered = Column(Boolean, default=False)
    risk_score = Column(Integer)
    verdict = Column(String)
    explanation = Column(JSON, default=dict)
    mitre_mappings = Column(JSON, default=list)
    details = Column(JSON)
    # NEW: weighted ensemble contribution breakdown
    risk_contributions = Column(JSON, default=dict)  # {"ml": 35, "threat_intel": 25, ...}
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AIFeedback(Base):
    __tablename__ = "ai_feedback"
    __table_args__ = (
        Index("ix_aifeedback_workspace_created", "workspace_id", "created_at"),
        Index("ix_aifeedback_workspace_status", "workspace_id", "review_status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_history.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    entity = Column(String)
    entity_type = Column(String) # url, email, web, network
    predicted_label = Column(String)
    actual_label = Column(String)
    confidence = Column(Float)
    risk_score = Column(Integer)
    feedback_type = Column(String) # false_positive, false_negative, wrong_category
    comments = Column(String, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    review_status = Column(String, default="pending") # pending, approved, rejected
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_workspace_created", "workspace_id", "created_at"),
        Index("ix_audit_action_created", "action", "created_at"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String)    # login_success, api_key_created, quota_exceeded, etc.
    module = Column(String)    # auth, workspace, agent
    status = Column(String)    # success, failure, warning
    event_metadata = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class UserBehaviorProfile(Base):
    __tablename__ = "user_behavior_profiles"
    __table_args__ = (
        Index("ix_uba_profile_workspace_user", "workspace_id", "user_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    average_daily_logins = Column(Integer, default=0)
    average_api_calls = Column(Integer, default=0)
    common_ip_addresses = Column(JSON, default=list)
    common_locations = Column(JSON, default=list)
    common_login_hours = Column(JSON, default=list)
    baseline_risk_score = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class UserBehaviorEvent(Base):
    __tablename__ = "user_behavior_events"
    __table_args__ = (
        Index("ix_uba_event_workspace_timestamp", "workspace_id", "timestamp"),
        Index("ix_uba_event_workspace_user", "workspace_id", "user_id"),
        Index("ix_uba_event_workspace_type", "workspace_id", "event_type"),
        Index("ix_uba_event_workspace_risk", "workspace_id", "risk_level"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    event_type = Column(String, index=True)
    ip_address = Column(String, index=True)
    location = Column(String)
    endpoint_accessed = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    anomaly_score = Column(Integer, default=0)
    risk_level = Column(String, default="NORMAL", index=True)
    explanation = Column(JSON, default=dict)


class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    __table_args__ = (
        Index("ix_threat_intel_active", "entity_value", "is_active"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_value = Column(String, unique=True, index=True)
    entity_type = Column(String)        # domain, ip
    threat_type = Column(String)        # phishing, malware, botnet
    risk_level = Column(String)         # low, medium, high, critical
    source = Column(String)             # local, abuseipdb, virustotal
    last_synced = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)


class Alert(Base):
    """Enterprise Alert Model for real-time threat notifications"""
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alert_workspace_created", "workspace_id", "created_at"),
        Index("ix_alert_workspace_severity", "workspace_id", "severity"),
        Index("ix_alert_workspace_resolved", "workspace_id", "resolved_status"),
        Index("ix_alert_entity_workspace", "entity", "workspace_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    scan_history_id = Column(UUID(as_uuid=True), ForeignKey("scan_history.id"), nullable=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)

    alert_type = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)

    entity = Column(String, nullable=False, index=True)
    entity_type = Column(String)
    source_vector = Column(String)

    risk_score = Column(Integer, nullable=False)
    ml_confidence = Column(Integer, default=0)
    # NEW: weighted ensemble contribution breakdown
    risk_contributions = Column(JSON, default=dict)

    indicators = Column(JSON)
    correlated_events = Column(Integer, default=0)
    recommended_action = Column(String)

    resolved_status = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    resolution_notes = Column(String, nullable=True)

    notification_sent = Column(Boolean, default=False)
    email_sent = Column(Boolean, default=False)
    webhook_sent = Column(Boolean, default=False)

    # NEW: false positive tracking
    false_positive_reported = Column(Boolean, default=False)
    in_review_queue = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AlertHistory(Base):
    """Tracks alert resolution and status changes for audit purposes"""
    __tablename__ = "alert_history"
    __table_args__ = (
        Index("ix_alert_history_alert", "alert_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    action = Column(String)             # created, resolved, escalated, snoozed
    previous_severity = Column(String)
    new_severity = Column(String)
    notes = Column(String)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class BlockedEntity(Base):
    """Blocked entities for Intrusion Prevention System"""
    __tablename__ = "blocked_entities"
    __table_args__ = (
        Index("ix_blocked_entity_workspace_entity", "workspace_id", "entity"),
        Index("ix_blocked_entity_workspace_expired", "workspace_id", "blocked_until"),
        Index("ix_blocked_entity_workspace_resolved", "workspace_id", "resolved_status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)

    entity = Column(String, nullable=False, index=True)
    entity_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    reason = Column(String, nullable=False)

    blocked_until = Column(DateTime(timezone=True), nullable=False, index=True)
    auto_generated = Column(Boolean, default=True)
    resolved_status = Column(Boolean, default=False, index=True)

    prevention_reason = Column(String)
    related_alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True)
    related_scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_history.id"), nullable=True)

    blocked_request_count = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    unblocked_at = Column(DateTime(timezone=True), nullable=True)
    unblocked_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


# ── NEW: False Positive Framework ─────────────────────────────────────────────

class FalsePositiveReport(Base):
    """User-submitted false positive reports for analyst review"""
    __tablename__ = "false_positive_reports"
    __table_args__ = (
        Index("ix_fp_report_workspace_status", "workspace_id", "status"),
        Index("ix_fp_report_scan", "scan_history_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    scan_history_id = Column(UUID(as_uuid=True), ForeignKey("scan_history.id"), nullable=True)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True)
    entity = Column(String, nullable=False, index=True)
    reported_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    reason = Column(Text, nullable=False)

    # Status: pending | confirmed | rejected
    status = Column(String, default="pending", index=True)
    reviewed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    reviewer_notes = Column(Text, nullable=True)

    # If confirmed FP, override any active blocks for this entity
    override_applied = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    reviewed_at = Column(DateTime(timezone=True), nullable=True)


class HumanReviewQueue(Base):
    """Items pending analyst review before a blocking action is committed"""
    __tablename__ = "human_review_queue"
    __table_args__ = (
        Index("ix_review_queue_workspace_status", "workspace_id", "status"),
        Index("ix_review_queue_entity", "workspace_id", "entity"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    entity = Column(String, nullable=False, index=True)
    entity_type = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)

    # Signals that triggered this review (JSON array of signal names)
    signals = Column(JSON, default=list)
    # Full risk contribution breakdown
    risk_contributions = Column(JSON, default=dict)
    # Related context
    scan_history_id = Column(UUID(as_uuid=True), ForeignKey("scan_history.id"), nullable=True)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True)

    # Status: pending | approved | rejected
    status = Column(String, default="pending", index=True)
    reviewed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    reviewer_notes = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    reviewed_at = Column(DateTime(timezone=True), nullable=True)


class SystemHealthLog(Base):
    """Periodic health snapshots for trending and alerting"""
    __tablename__ = "system_health_logs"
    __table_args__ = (
        Index("ix_health_log_service_time", "service", "checked_at"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    service = Column(String, nullable=False, index=True)  # database, redis, worker, threat_intel
    status = Column(String, nullable=False)               # ok, degraded, unavailable
    latency_ms = Column(Float, nullable=True)
    detail = Column(JSON, nullable=True)
    checked_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_workspace_incident", "workspace_id", "incident_alert_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False)
    incident_alert_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    evidence_type = Column(String, nullable=False)
    source = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    value_indicator = Column(String, nullable=True)
    confidence = Column(Integer, default=0)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    importance = Column(String, default="MEDIUM")
    supporting_entity_id = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

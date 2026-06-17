"""
Enterprise Alert Service for CyberGuard AI
Handles alert generation, severity calculation, and notification orchestration
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import uuid as uuid_lib
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from src.models.models import Alert, AlertHistory, AuditLog, ScanHistory, ThreatIntel
from src.utils.audit import AuditLogger


class AlertSeverity:
    """Alert severity level mapping"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    
    @staticmethod
    def from_risk_score(score: int) -> str:
        """Map risk score (0-100) to severity level"""
        if score >= 86:
            return AlertSeverity.CRITICAL
        elif score >= 61:
            return AlertSeverity.HIGH
        elif score >= 31:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    @staticmethod
    def get_color(severity: str) -> str:
        """Return color code for severity level"""
        colors = {
            AlertSeverity.LOW: "#10b981",
            AlertSeverity.MEDIUM: "#f59e0b",
            AlertSeverity.HIGH: "#f97316",
            AlertSeverity.CRITICAL: "#ef4444",
        }
        return colors.get(severity, "#6b7280")


class AlertService:
    """
    Enterprise alert generation and management service
    Implements real-time threat alerting with multi-vector correlation
    """
    
    # Alert cooldown period to avoid duplicate alerts (in minutes)
    DUPLICATE_ALERT_COOLDOWN = 60
    
    # Time window for repeated entity detection (in hours)
    REPEATED_ENTITY_WINDOW = 24
    
    # Anomaly severity thresholds
    NETWORK_ANOMALY_THRESHOLD = 70
    
    @staticmethod
    def calculate_alert_severity(
        risk_score: int,
        has_blacklist_match: bool = False,
        has_correlation: bool = False,
        ml_confidence: int = 0,
    ) -> str:
        """
        Calculate alert severity based on multiple factors
        
        Args:
            risk_score: Primary risk score (0-100)
            has_blacklist_match: Whether entity matches threat intelligence
            has_correlation: Whether indicators are correlated
            ml_confidence: ML model confidence percentage
            
        Returns:
            Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        severity = AlertSeverity.from_risk_score(risk_score)
        
        # Escalate severity if blacklist match
        if has_blacklist_match:
            if severity in [AlertSeverity.LOW, AlertSeverity.MEDIUM]:
                severity = AlertSeverity.HIGH
            elif severity == AlertSeverity.HIGH:
                severity = AlertSeverity.CRITICAL
        
        # Escalate severity if correlated
        if has_correlation and severity != AlertSeverity.CRITICAL:
            severity = AlertSeverity.HIGH
        
        # Escalate if high ML confidence on high risk
        if ml_confidence >= 90 and severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            if severity == AlertSeverity.HIGH:
                severity = AlertSeverity.CRITICAL
        
        return severity
    
    @staticmethod
    def should_generate_alert(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str,
        risk_score: int,
        alert_type: str,
    ) -> bool:
        """
        Determine if alert should be generated based on:
        1. Risk score threshold (>= 70)
        2. Duplicate alert cooldown
        3. Recent entity reputation
        
        Args:
            db: Database session
            workspace_id: Workspace ID
            entity: Entity value (domain, IP, etc.)
            risk_score: Risk score 0-100
            alert_type: Type of alert
            
        Returns:
            True if alert should be generated
        """
        # Always alert on high-risk scores
        if risk_score < 70:
            return False
        
        # Check for duplicate alerts within cooldown period
        cooldown_time = datetime.utcnow() - timedelta(minutes=AlertService.DUPLICATE_ALERT_COOLDOWN)
        recent_alert = db.query(Alert).filter(
            and_(
                Alert.workspace_id == workspace_id,
                Alert.entity == entity,
                Alert.alert_type == alert_type,
                Alert.created_at > cooldown_time,
                Alert.resolved_status == False,
            )
        ).first()
        
        if recent_alert:
            return False
        
        return True
    
    @staticmethod
    def check_repeated_entity(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str,
        entity_type: str,
    ) -> Dict[str, Any]:
        """
        Check if entity has appeared multiple times within time window
        Returns escalation indicators if suspicious pattern detected
        
        Args:
            db: Database session
            workspace_id: Workspace ID
            entity: Entity value
            entity_type: Type of entity (domain, ip, email, etc.)
            
        Returns:
            Dictionary with correlated_count and escalation_factor
        """
        time_window = datetime.utcnow() - timedelta(hours=AlertService.REPEATED_ENTITY_WINDOW)
        
        # Check scan history for repeated occurrences
        correlated = db.query(ScanHistory).filter(
            and_(
                ScanHistory.workspace_id == workspace_id,
                ScanHistory.entity == entity,
                ScanHistory.created_at > time_window,
            )
        ).all()
        
        # Check for alerts on same entity
        alert_count = db.query(Alert).filter(
            and_(
                Alert.workspace_id == workspace_id,
                Alert.entity == entity,
                Alert.created_at > time_window,
            )
        ).count()
        
        total_occurrences = len(correlated) + alert_count
        
        return {
            "correlated_count": total_occurrences,
            "escalation_factor": min(10, total_occurrences * 2),  # Max +10 to risk score
            "is_repeated_entity": total_occurrences >= 3,
        }
    
    @staticmethod
    def generate_alert(
        db: Session,
        workspace_id: uuid_lib.UUID,
        user_id: Optional[uuid_lib.UUID],
        scan_history_id: Optional[uuid_lib.UUID],
        scan_result: Dict[str, Any],
        entity: str,
        entity_type: str,
        risk_score: int,
        intelligence_result: Optional[Dict[str, Any]] = None,
        correlation_result: Optional[Dict[str, Any]] = None,
    ) -> Optional[Alert]:
        """
        Generate alert from scan result
        
        Args:
            db: Database session
            workspace_id: Workspace ID
            user_id: User ID (optional)
            scan_history_id: Related scan history ID
            scan_result: Detection service result
            entity: Entity being scanned
            entity_type: Type of entity
            risk_score: Calculated risk score
            intelligence_result: Threat intelligence result
            correlation_result: Correlation engine result
            
        Returns:
            Created Alert object or None if not generated
        """
        # Determine alert type and source vector
        source_vector = scan_result.get("vector", "UNKNOWN")
        attack_type = scan_result.get("attack_type", "UNKNOWN")
        alert_type = AlertService._map_alert_type(attack_type, source_vector)
        
        # Check if alert should be generated
        if not AlertService.should_generate_alert(
            db, workspace_id, entity, risk_score, alert_type
        ):
            return None
        
        # Check for repeated entity
        repeated_info = AlertService.check_repeated_entity(
            db, workspace_id, entity, entity_type
        )
        
        # Adjust risk score based on repeated entity pattern
        adjusted_risk_score = min(100, risk_score + repeated_info.get("escalation_factor", 0))
        
        # Check for blacklist match
        has_blacklist_match = intelligence_result is not None and intelligence_result.get("hit", False)
        has_correlation = correlation_result is not None and correlation_result.get("detected", False)
        
        # Calculate final severity
        severity = AlertService.calculate_alert_severity(
            adjusted_risk_score,
            has_blacklist_match=has_blacklist_match,
            has_correlation=has_correlation,
            ml_confidence=scan_result.get("confidence", 0),
        )
        
        # Generate alert title and description
        title, description = AlertService._generate_alert_messages(
            attack_type, entity, severity, repeated_info
        )
        
        # Collect indicators
        indicators = AlertService._collect_indicators(
            scan_result, intelligence_result, correlation_result
        )
        
        # Recommended action
        recommended_action = AlertService._get_recommended_action(
            alert_type, severity, entity
        )
        
        # Create alert
        alert = Alert(
            workspace_id=workspace_id,
            user_id=user_id,
            scan_history_id=scan_history_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            entity=entity,
            entity_type=entity_type,
            source_vector=source_vector,
            risk_score=adjusted_risk_score,
            ml_confidence=int(scan_result.get("confidence", 0)),
            indicators=indicators,
            correlated_events=repeated_info.get("correlated_count", 0),
            recommended_action=recommended_action,
            resolved_status=False,
        )
        
        db.add(alert)
        db.flush()
        
        # Log alert creation to audit log
        AuditLogger.log(
            db,
            action="alert_generated",
            module="alert_service",
            status="success",
            workspace_id=workspace_id,
            user_id=user_id,
            metadata={
                "alert_id": str(alert.id),
                "severity": severity,
                "risk_score": adjusted_risk_score,
                "entity": entity,
                "alert_type": alert_type,
                "has_blacklist_match": has_blacklist_match,
                "has_correlation": has_correlation,
            }
        )
        
        db.commit()
        return alert
    
    @staticmethod
    def _map_alert_type(attack_type: str, vector: str) -> str:
        """Map attack type to alert type"""
        attack_type_lower = attack_type.lower()
        
        type_mapping = {
            "phishing": "phishing",
            "malware": "malware",
            "credential-harvest": "credential_harvest",
            "sql injection": "sql_injection",
            "cross-site scripting": "xss",
            "directory traversal": "lfi_rfi",
            "network anomaly": "network_anomaly",
            "botnet": "botnet_detection",
            "command-and-control": "c2_detection",
        }
        
        for key, value in type_mapping.items():
            if key in attack_type_lower:
                return value
        
        return f"{vector.lower()}_attack"
    
    @staticmethod
    def _generate_alert_messages(
        attack_type: str,
        entity: str,
        severity: str,
        repeated_info: Dict[str, Any],
    ) -> tuple:
        """Generate alert title and description"""
        
        is_repeated = repeated_info.get("is_repeated_entity", False)
        repeat_count = repeated_info.get("correlated_count", 0)
        
        title_templates = {
            "CRITICAL": f"🚨 CRITICAL: {attack_type} Threat Detected",
            "HIGH": f"⚠️ HIGH: {attack_type} Threat Detected",
            "MEDIUM": f"⚡ MEDIUM: {attack_type} Detected",
            "LOW": f"ℹ️ LOW: {attack_type} Detected",
        }
        
        title = title_templates.get(severity, f"{attack_type} Alert")
        
        base_desc = f"Entity '{entity}' detected as {attack_type}. "
        
        if is_repeated:
            description = (
                f"{base_desc}This entity has appeared {repeat_count} times in the last 24 hours. "
                f"Pattern suggests persistent threat activity. Immediate investigation recommended."
            )
        else:
            description = (
                f"{base_desc}Risk assessed at {severity.lower()} level. "
                f"Review scan details and take appropriate action."
            )
        
        return title, description
    
    @staticmethod
    def _collect_indicators(
        scan_result: Dict[str, Any],
        intelligence_result: Optional[Dict[str, Any]] = None,
        correlation_result: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, str]]:
        """Collect attack indicators from multiple sources"""
        
        indicators = []
        
        # ML indicators
        if scan_result.get("attack_type"):
            indicators.append({
                "type": "attack_type",
                "value": scan_result["attack_type"],
                "source": "ml_detection",
            })
        
        # Intelligence indicators
        if intelligence_result:
            if intelligence_result.get("threat_type"):
                indicators.append({
                    "type": "threat_type",
                    "value": intelligence_result["threat_type"],
                    "source": "threat_intel",
                })
            if intelligence_result.get("risk_level"):
                indicators.append({
                    "type": "risk_level",
                    "value": intelligence_result["risk_level"],
                    "source": "threat_intel",
                })
        
        # Correlation indicators
        if correlation_result and correlation_result.get("rules_triggered"):
            for rule in correlation_result["rules_triggered"]:
                indicators.append({
                    "type": "correlation_rule",
                    "value": rule,
                    "source": "correlation_engine",
                })
        
        return indicators
    
    @staticmethod
    def _get_recommended_action(alert_type: str, severity: str, entity: str) -> str:
        """Get recommended action based on alert type and severity"""
        
        action_map = {
            "phishing": f"Block domain '{entity}' and notify users. Review phishing emails.",
            "malware": f"Isolate systems accessing '{entity}'. Scan for infections.",
            "credential_harvest": f"Change credentials immediately. Monitor account access. Block '{entity}'.",
            "sql_injection": f"Apply WAF rules against SQL injection. Review logs for exploitation.",
            "xss": f"Patch vulnerable input filters. Implement CSP headers.",
            "network_anomaly": f"Investigate unusual traffic patterns. Check for unauthorized access.",
            "botnet_detection": f"Block IP '{entity}'. Scan systems for malware.",
            "c2_detection": f"Isolate affected systems. Block C2 domain '{entity}' at firewall.",
        }
        
        default = f"Investigate entity '{entity}'. Review alert details and apply appropriate countermeasures."
        
        return action_map.get(alert_type, default)
    
    @staticmethod
    def get_alerts(
        db: Session,
        workspace_id: uuid_lib.UUID,
        severity: Optional[str] = None,
        resolved: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple:
        """
        Get alerts with optional filtering
        
        Returns:
            (alerts list, total count)
        """
        query = db.query(Alert).filter(Alert.workspace_id == workspace_id)
        
        if severity:
            query = query.filter(Alert.severity == severity)
        
        if resolved is not None:
            query = query.filter(Alert.resolved_status == resolved)
        
        total = query.count()
        
        alerts = query.order_by(desc(Alert.created_at)).offset(offset).limit(limit).all()
        
        return alerts, total
    
    @staticmethod
    def get_unresolved_alert_count(
        db: Session,
        workspace_id: uuid_lib.UUID,
    ) -> Dict[str, int]:
        """Get count of unresolved alerts by severity"""
        
        severities = [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]
        counts = {}
        
        for severity in severities:
            count = db.query(Alert).filter(
                and_(
                    Alert.workspace_id == workspace_id,
                    Alert.severity == severity,
                    Alert.resolved_status == False,
                )
            ).count()
            counts[severity] = count
        
        return counts
    
    @staticmethod
    def resolve_alert(
        db: Session,
        alert_id: uuid_lib.UUID,
        user_id: uuid_lib.UUID,
        resolution_notes: Optional[str] = None,
    ) -> Optional[Alert]:
        """
        Mark alert as resolved
        
        Args:
            db: Database session
            alert_id: Alert ID
            user_id: User resolving the alert
            resolution_notes: Optional notes about resolution
            
        Returns:
            Updated Alert or None if not found
        """
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        
        if not alert:
            return None
        
        alert.resolved_status = True
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = user_id
        alert.resolution_notes = resolution_notes
        
        db.flush()
        
        # Log resolution to alert history
        history = AlertHistory(
            alert_id=alert_id,
            workspace_id=alert.workspace_id,
            user_id=user_id,
            action="resolved",
            previous_severity=alert.severity,
            notes=resolution_notes,
        )
        db.add(history)
        
        # Log to audit log
        AuditLogger.log(
            db,
            action="alert_resolved",
            module="alert_service",
            status="success",
            workspace_id=alert.workspace_id,
            user_id=user_id,
            metadata={
                "alert_id": str(alert_id),
                "severity": alert.severity,
                "resolution_notes": resolution_notes,
            }
        )
        
        db.commit()
        return alert
    
    @staticmethod
    def get_alert_stats(
        db: Session,
        workspace_id: uuid_lib.UUID,
        time_hours: int = 24,
    ) -> Dict[str, Any]:
        """
        Get alert statistics for workspace
        
        Args:
            db: Database session
            workspace_id: Workspace ID
            time_hours: Time period to analyze
            
        Returns:
            Dictionary with alert statistics
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=time_hours)
        
        total_alerts = db.query(Alert).filter(
            and_(
                Alert.workspace_id == workspace_id,
                Alert.created_at > cutoff_time,
            )
        ).count()
        
        resolved_alerts = db.query(Alert).filter(
            and_(
                Alert.workspace_id == workspace_id,
                Alert.created_at > cutoff_time,
                Alert.resolved_status == True,
            )
        ).count()
        
        unresolved_alerts = total_alerts - resolved_alerts
        
        # Get unresolved by severity
        unresolved_by_severity = AlertService.get_unresolved_alert_count(db, workspace_id)
        
        # Top alert types
        top_types = db.query(
            Alert.alert_type,
            db.func.count(Alert.id).label("count")
        ).filter(
            and_(
                Alert.workspace_id == workspace_id,
                Alert.created_at > cutoff_time,
            )
        ).group_by(Alert.alert_type).order_by(desc("count")).limit(5).all()
        
        top_entities = db.query(
            Alert.entity,
            db.func.count(Alert.id).label("count")
        ).filter(
            and_(
                Alert.workspace_id == workspace_id,
                Alert.created_at > cutoff_time,
            )
        ).group_by(Alert.entity).order_by(desc("count")).limit(5).all()
        
        return {
            "total_alerts": total_alerts,
            "resolved_alerts": resolved_alerts,
            "unresolved_alerts": unresolved_alerts,
            "unresolved_by_severity": unresolved_by_severity,
            "top_alert_types": [{"type": t[0], "count": t[1]} for t in top_types],
            "top_entities": [{"entity": e[0], "count": e[1]} for e in top_entities],
        }

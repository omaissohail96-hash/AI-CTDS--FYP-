"""
Intrusion Prevention Engine for CyberGuard AI
Automated threat response and entity blocking system
Automatically executes prevention actions against detected threats
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import uuid as uuid_lib
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from src.models.models import BlockedEntity, Alert, ScanHistory, AuditLog
from src.utils.audit import AuditLogger


class PreventionDuration:
    """Prevention duration policies based on severity"""
    MEDIUM = 1 * 60 * 60  # 1 hour in seconds
    HIGH = 24 * 60 * 60  # 24 hours
    CRITICAL = 7 * 24 * 60 * 60  # 7 days


class PreventionReason:
    """Predefined prevention reasons"""
    HIGH_RISK_SCORE = "High risk score (>= 90)"
    REPEATED_ATTACKS = "Multiple attacks from same entity within time window"
    KNOWN_MALICIOUS = "Entity matched known malicious blacklist"
    CRITICAL_ANOMALY = "Critical network anomaly detected"
    PHISHING_DETECTION = "Phishing URL or malicious domain detected"
    AUTO_ESCALATION = "Auto-escalated from correlation engine"


class PreventionEngine:
    """
    Enterprise-grade Intrusion Prevention System
    Automatically responds to detected threats with dynamic blocking and blacklisting
    """
    
    # Configurable prevention thresholds
    RISK_SCORE_AUTO_BLOCK = 90  # Auto-block threshold
    REPEATED_ATTACK_THRESHOLD = 3  # Number of attacks before temp ban
    REPEATED_ATTACK_WINDOW = 3600  # Time window in seconds (1 hour)
    
    @staticmethod
    def evaluate_threat(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str,
        entity_type: str,
        risk_score: int,
        threat_context: Dict[str, Any],
        alert_id: Optional[uuid_lib.UUID] = None,
        scan_id: Optional[uuid_lib.UUID] = None,
        user_id: Optional[uuid_lib.UUID] = None
    ) -> Tuple[bool, Optional[BlockedEntity]]:
        """
        Evaluate threat and determine if prevention action should be taken.
        Returns (should_block, blocked_entity_object)
        """
        
        # Check if entity is already blocked
        existing_block = PreventionEngine.get_blocked_entity(db, workspace_id, entity)
        if existing_block and not existing_block.resolved_status:
            return True, existing_block
        
        prevention_action = None
        reason = None
        duration = None
        
        # Rule 1: High risk score auto-block
        if risk_score >= PreventionEngine.RISK_SCORE_AUTO_BLOCK:
            prevention_action = True
            reason = PreventionReason.HIGH_RISK_SCORE
            duration = PreventionDuration.CRITICAL
        
        # Rule 2: Repeated attacks detection
        elif entity_type in ["IP", "DOMAIN"]:
            repeated_count = PreventionEngine.check_repeated_attacks(
                db,
                workspace_id,
                entity,
                window_seconds=PreventionEngine.REPEATED_ATTACK_WINDOW
            )
            if repeated_count >= PreventionEngine.REPEATED_ATTACK_THRESHOLD:
                prevention_action = True
                reason = PreventionReason.REPEATED_ATTACKS
                duration = PreventionDuration.HIGH
        
        # Rule 3: Known malicious entity check
        if not prevention_action and threat_context.get("intelligence_hit"):
            prevention_action = True
            reason = PreventionReason.KNOWN_MALICIOUS
            duration = PreventionDuration.CRITICAL
        
        # Rule 4: Critical network anomaly
        if not prevention_action and threat_context.get("severity") == "CRITICAL":
            prevention_action = True
            reason = PreventionReason.CRITICAL_ANOMALY
            duration = PreventionDuration.HIGH
        
        # Rule 5: Phishing/malicious URL detection
        if not prevention_action and entity_type == "URL" and risk_score >= 70:
            prevention_action = True
            reason = PreventionReason.PHISHING_DETECTION
            duration = PreventionDuration.HIGH
        
        if prevention_action and duration:
            blocked_entity = PreventionEngine.create_block(
                db,
                workspace_id=workspace_id,
                entity=entity,
                entity_type=entity_type,
                severity=threat_context.get("severity", "HIGH"),
                reason=reason,
                duration_seconds=duration,
                alert_id=alert_id,
                scan_id=scan_id,
                user_id=user_id,
                auto_generated=True
            )
            return True, blocked_entity
        
        return False, None
    
    @staticmethod
    def create_block(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str,
        entity_type: str,
        severity: str,
        reason: str,
        duration_seconds: int = 86400,  # Default 24 hours
        alert_id: Optional[uuid_lib.UUID] = None,
        scan_id: Optional[uuid_lib.UUID] = None,
        user_id: Optional[uuid_lib.UUID] = None,
        auto_generated: bool = True,
        prevention_reason: Optional[str] = None
    ) -> BlockedEntity:
        """
        Create a new blocked entity entry
        """
        
        now = datetime.utcnow()
        blocked_until = now + timedelta(seconds=duration_seconds)
        
        blocked_entity = BlockedEntity(
            workspace_id=workspace_id,
            entity=entity,
            entity_type=entity_type,
            severity=severity,
            reason=reason,
            blocked_until=blocked_until,
            auto_generated=auto_generated,
            resolved_status=False,
            prevention_reason=prevention_reason or reason,
            related_alert_id=alert_id,
            related_scan_id=scan_id,
            created_by=user_id,
            blocked_request_count=0
        )
        
        db.add(blocked_entity)
        db.flush()
        
        # Log prevention action to audit log
        AuditLogger.log(
            db,
            action="entity_blocked",
            module="prevention_engine",
            status="success",
            workspace_id=workspace_id,
            user_id=user_id,
            metadata={
                "entity": entity,
                "entity_type": entity_type,
                "severity": severity,
                "reason": reason,
                "blocked_until": blocked_until.isoformat(),
                "auto_generated": auto_generated,
            }
        )
        
        db.commit()
        return blocked_entity
    
    @staticmethod
    def get_blocked_entity(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str
    ) -> Optional[BlockedEntity]:
        """
        Retrieve a blocked entity from database
        """
        return db.query(BlockedEntity).filter(
            and_(
                BlockedEntity.workspace_id == workspace_id,
                BlockedEntity.entity == entity
            )
        ).first()
    
    @staticmethod
    def is_entity_blocked(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str
    ) -> bool:
        """
        Check if entity is currently blocked (and not expired)
        """
        blocked = PreventionEngine.get_blocked_entity(db, workspace_id, entity)
        
        if not blocked or blocked.resolved_status:
            return False
        
        # Check if block has expired
        if blocked.blocked_until < datetime.utcnow():
            return False
        
        return True
    
    @staticmethod
    def check_repeated_attacks(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str,
        window_seconds: int = 3600
    ) -> int:
        """
        Check number of attacks from the same entity within a time window
        """
        cutoff_time = datetime.utcnow() - timedelta(seconds=window_seconds)
        
        count = db.query(ScanHistory).filter(
            and_(
                ScanHistory.workspace_id == workspace_id,
                ScanHistory.entity == entity,
                ScanHistory.created_at >= cutoff_time,
                ScanHistory.verdict.in_(["malicious", "MALICIOUS"])
            )
        ).count()
        
        return count
    
    @staticmethod
    def increment_blocked_request_count(
        db: Session,
        blocked_entity_id: uuid_lib.UUID
    ) -> None:
        """
        Increment blocked request counter for statistics
        """
        blocked_entity = db.query(BlockedEntity).filter(
            BlockedEntity.id == blocked_entity_id
        ).first()
        
        if blocked_entity:
            blocked_entity.blocked_request_count += 1
            db.commit()
    
    @staticmethod
    def unblock_entity(
        db: Session,
        workspace_id: uuid_lib.UUID,
        blocked_entity_id: uuid_lib.UUID,
        user_id: Optional[uuid_lib.UUID] = None
    ) -> BlockedEntity:
        """
        Manually unblock an entity
        """
        blocked_entity = db.query(BlockedEntity).filter(
            and_(
                BlockedEntity.id == blocked_entity_id,
                BlockedEntity.workspace_id == workspace_id
            )
        ).first()
        
        if not blocked_entity:
            raise ValueError(f"Blocked entity {blocked_entity_id} not found")
        
        blocked_entity.resolved_status = True
        blocked_entity.unblocked_at = datetime.utcnow()
        blocked_entity.unblocked_by = user_id
        
        # Log unblock action
        AuditLogger.log(
            db,
            action="entity_unblocked",
            module="prevention_engine",
            status="success",
            workspace_id=workspace_id,
            user_id=user_id,
            metadata={
                "entity": blocked_entity.entity,
                "entity_type": blocked_entity.entity_type,
                "reason": blocked_entity.reason,
            }
        )
        
        db.commit()
        return blocked_entity
    
    @staticmethod
    def cleanup_expired_blocks(db: Session) -> int:
        """
        Cleanup expired blocks and mark them as resolved
        Returns count of entities unblocked
        """
        now = datetime.utcnow()
        
        expired_blocks = db.query(BlockedEntity).filter(
            and_(
                BlockedEntity.blocked_until < now,
                BlockedEntity.resolved_status == False
            )
        ).all()
        
        for block in expired_blocks:
            block.resolved_status = True
            block.unblocked_at = now
        
        db.commit()
        return len(expired_blocks)
    
    @staticmethod
    def get_blocked_entities(
        db: Session,
        workspace_id: uuid_lib.UUID,
        skip: int = 0,
        limit: int = 50,
        active_only: bool = True,
        entity_type_filter: Optional[str] = None,
        severity_filter: Optional[str] = None
    ) -> Tuple[List[BlockedEntity], int]:
        """
        Get paginated list of blocked entities
        """
        query = db.query(BlockedEntity).filter(
            BlockedEntity.workspace_id == workspace_id
        )
        
        if active_only:
            now = datetime.utcnow()
            query = query.filter(
                and_(
                    BlockedEntity.blocked_until > now,
                    BlockedEntity.resolved_status == False
                )
            )
        
        if entity_type_filter:
            query = query.filter(BlockedEntity.entity_type == entity_type_filter)
        
        if severity_filter:
            query = query.filter(BlockedEntity.severity == severity_filter)
        
        total = query.count()
        
        entities = query.order_by(
            desc(BlockedEntity.created_at)
        ).offset(skip).limit(limit).all()
        
        return entities, total
    
    @staticmethod
    def get_prevention_stats(
        db: Session,
        workspace_id: uuid_lib.UUID
    ) -> Dict[str, Any]:
        """
        Get prevention statistics for workspace
        """
        now = datetime.utcnow()
        
        # Active blocks
        active_blocks = db.query(BlockedEntity).filter(
            and_(
                BlockedEntity.workspace_id == workspace_id,
                BlockedEntity.blocked_until > now,
                BlockedEntity.resolved_status == False
            )
        ).count()
        
        # Blocks by severity
        severity_stats = {}
        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            count = db.query(BlockedEntity).filter(
                and_(
                    BlockedEntity.workspace_id == workspace_id,
                    BlockedEntity.severity == severity,
                    BlockedEntity.blocked_until > now,
                    BlockedEntity.resolved_status == False
                )
            ).count()
            severity_stats[severity] = count
        
        # Blocks by entity type
        type_stats = {}
        for entity_type in ["IP", "URL", "DOMAIN"]:
            count = db.query(BlockedEntity).filter(
                and_(
                    BlockedEntity.workspace_id == workspace_id,
                    BlockedEntity.entity_type == entity_type,
                    BlockedEntity.blocked_until > now,
                    BlockedEntity.resolved_status == False
                )
            ).count()
            type_stats[entity_type] = count
        
        # Total requests blocked (24h)
        cutoff_24h = now - timedelta(hours=24)
        recent_blocks = db.query(BlockedEntity).filter(
            and_(
                BlockedEntity.workspace_id == workspace_id,
                BlockedEntity.created_at >= cutoff_24h
            )
        ).all()
        
        total_blocked_requests = sum(b.blocked_request_count for b in recent_blocks)
        
        # Auto-generated vs manual blocks
        auto_blocks = db.query(BlockedEntity).filter(
            and_(
                BlockedEntity.workspace_id == workspace_id,
                BlockedEntity.auto_generated == True,
                BlockedEntity.blocked_until > now,
                BlockedEntity.resolved_status == False
            )
        ).count()
        
        manual_blocks = active_blocks - auto_blocks
        
        return {
            "active_blocks_count": active_blocks,
            "total_blocked_requests_24h": total_blocked_requests,
            "blocks_by_severity": severity_stats,
            "blocks_by_entity_type": type_stats,
            "auto_generated_blocks": auto_blocks,
            "manual_blocks": manual_blocks,
            "auto_unblock_scheduled": active_blocks  # All active blocks have auto-unblock
        }
    
    @staticmethod
    def get_prevention_history(
        db: Session,
        workspace_id: uuid_lib.UUID,
        skip: int = 0,
        limit: int = 50,
        hours: int = 24
    ) -> Tuple[List[BlockedEntity], int]:
        """
        Get prevention history for recent period
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        query = db.query(BlockedEntity).filter(
            and_(
                BlockedEntity.workspace_id == workspace_id,
                BlockedEntity.created_at >= cutoff_time
            )
        )
        
        total = query.count()
        
        history = query.order_by(
            desc(BlockedEntity.created_at)
        ).offset(skip).limit(limit).all()
        
        return history, total
    
    @staticmethod
    def get_prevention_reasoning(
        db: Session,
        blocked_entity_id: uuid_lib.UUID
    ) -> str:
        """
        Generate detailed reasoning for why entity was blocked
        """
        block = db.query(BlockedEntity).filter(
            BlockedEntity.id == blocked_entity_id
        ).first()
        
        if not block:
            return "Entity not found"
        
        reasoning = f"""
This {block.entity_type} ({block.entity}) was automatically blocked because:

1. **Reason**: {block.reason}
2. **Severity Level**: {block.severity}
3. **Prevention Policy**: {block.prevention_reason}

Block Duration:
- Created: {block.created_at.strftime('%Y-%m-%d %H:%M:%S')} UTC
- Expires: {block.blocked_until.strftime('%Y-%m-%d %H:%M:%S')} UTC

Statistics:
- Blocked Requests: {block.blocked_request_count}
- Auto-Generated: {'Yes' if block.auto_generated else 'No'}

Related Investigation:
- Alert ID: {block.related_alert_id if block.related_alert_id else 'N/A'}
- Scan ID: {block.related_scan_id if block.related_scan_id else 'N/A'}

This entity poses a significant threat and has been automatically quarantined
until the configured prevention duration expires or manual intervention occurs.
        """.strip()
        
        return reasoning

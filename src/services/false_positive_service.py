"""
False Positive Reduction Framework for CyberGuard AI.

Prevents single-signal blocking by enforcing multi-signal consensus rules
before any entity is automatically blocked.

Blocking Requirements:
  (ML High + TI Hit)
  OR (3+ independent detections within 24h)
  OR (Repeated malicious activity >= FP_REPEATED_DETECTION_COUNT)

Entities failing these thresholds but above REVIEW_QUEUE_THRESHOLD
are queued for human analyst review instead.
"""

import logging
import uuid as uuid_lib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class SignalSet:
    """Named constants for detection signals."""
    ML_HIGH       = "ml_high_confidence"
    THREAT_INTEL  = "threat_intelligence_hit"
    CORRELATION   = "correlation_pattern"
    UBA_ANOMALY   = "uba_anomaly"
    REPEATED_ATK  = "repeated_attacks"


class FalsePositiveFramework:
    """
    Enterprise false positive prevention service.

    All blocking decisions must pass through `should_block()` before
    any entity is added to the `blocked_entities` table.
    """

    @staticmethod
    def _get_settings():
        from src.core.config import settings
        return settings

    @staticmethod
    def detect_signals(
        risk_score: int,
        ml_score: float,
        threat_intel: Optional[Dict],
        correlation: Optional[Dict],
        uba: Optional[Dict],
    ) -> List[str]:
        """
        Identify which detection signals are active for this entity.
        Returns a list of signal names from SignalSet.
        """
        cfg = FalsePositiveFramework._get_settings()
        signals = []

        if ml_score >= cfg.FP_ML_HIGH_THRESHOLD:
            signals.append(SignalSet.ML_HIGH)

        if threat_intel and threat_intel.get("risk_level") in ("high", "critical", "medium"):
            signals.append(SignalSet.THREAT_INTEL)

        if correlation and correlation.get("detected"):
            signals.append(SignalSet.CORRELATION)

        if uba and uba.get("score", 0) >= 60:
            signals.append(SignalSet.UBA_ANOMALY)

        return signals

    @staticmethod
    def should_block(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str,
        entity_type: str,
        risk_score: int,
        signals: List[str],
        threat_context: Dict[str, Any],
    ) -> Tuple[bool, bool, str]:
        """
        Evaluate whether an entity should be blocked, queued for review,
        or simply alerted on.

        Returns:
            (should_block, queue_for_review, reason)

        Decision matrix:
          - ML_HIGH + THREAT_INTEL  → block
          - ML_HIGH + CORRELATION   → block
          - THREAT_INTEL alone       → block (external verification is strong)
          - REPEATED_ATTACKS         → block
          - Risk >= 70 but no multi-signal → queue for review
          - Risk < 70               → alert only
        """
        cfg = FalsePositiveFramework._get_settings()

        # Rule 1: Threat Intel alone is a trusted external signal — allow block
        if SignalSet.THREAT_INTEL in signals:
            return True, False, "Threat intelligence blacklist confirmation"

        # Rule 2: ML High + secondary signal
        if SignalSet.ML_HIGH in signals and len(signals) >= cfg.FP_MULTI_SIGNAL_COUNT:
            secondary = [s for s in signals if s != SignalSet.ML_HIGH]
            return True, False, f"ML high confidence + corroborating signal(s): {', '.join(secondary)}"

        # Rule 3: Repeated attacks
        if FalsePositiveFramework._check_repeated_attacks(db, workspace_id, entity, cfg):
            return True, False, "Repeated malicious activity exceeds threshold"

        # Rule 4: High risk but insufficient signals → human review
        if risk_score >= cfg.FP_REVIEW_QUEUE_THRESHOLD:
            return False, True, f"Risk score {risk_score} below multi-signal block threshold — queued for review"

        # No block, no review
        return False, False, "Insufficient signals for automated action"

    @staticmethod
    def _check_repeated_attacks(db: Session, workspace_id, entity: str, cfg) -> bool:
        """Check if entity has enough repeated malicious detections to trigger a block."""
        try:
            from src.models.models import ScanHistory
            cutoff = datetime.utcnow() - timedelta(hours=cfg.FP_REPEATED_DETECTION_WINDOW_HOURS)
            count = db.query(ScanHistory).filter(
                and_(
                    ScanHistory.workspace_id == workspace_id,
                    ScanHistory.entity == entity,
                    ScanHistory.created_at >= cutoff,
                    ScanHistory.verdict.in_(["CRITICAL", "HIGH", "malicious", "MALICIOUS"]),
                )
            ).count()
            return count >= cfg.FP_REPEATED_DETECTION_COUNT
        except Exception as exc:
            logger.warning(f"Repeated attack check failed: {exc}")
            return False

    @staticmethod
    def create_review_queue_item(
        db: Session,
        workspace_id: uuid_lib.UUID,
        entity: str,
        entity_type: str,
        risk_score: int,
        signals: List[str],
        risk_contributions: Dict,
        scan_id: Optional[uuid_lib.UUID] = None,
        alert_id: Optional[uuid_lib.UUID] = None,
    ) -> Any:
        """
        Add an entity to the human review queue.
        Returns the HumanReviewQueue object.
        """
        from src.models.models import HumanReviewQueue
        item = HumanReviewQueue(
            workspace_id=workspace_id,
            entity=entity,
            entity_type=entity_type,
            risk_score=risk_score,
            signals=signals,
            risk_contributions=risk_contributions,
            scan_history_id=scan_id,
            alert_id=alert_id,
            status="pending",
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        logger.info(f"Entity {entity} added to human review queue (risk={risk_score})")
        return item

    @staticmethod
    def submit_false_positive(
        db: Session,
        workspace_id: uuid_lib.UUID,
        reported_by: uuid_lib.UUID,
        entity: str,
        reason: str,
        scan_history_id: Optional[uuid_lib.UUID] = None,
        alert_id: Optional[uuid_lib.UUID] = None,
    ) -> Any:
        """
        Submit a false positive report for an entity.
        Also marks associated alert with `false_positive_reported = True`.
        """
        from src.models.models import FalsePositiveReport, Alert

        report = FalsePositiveReport(
            workspace_id=workspace_id,
            reported_by=reported_by,
            entity=entity,
            reason=reason,
            scan_history_id=scan_history_id,
            alert_id=alert_id,
            status="pending",
        )
        db.add(report)

        if alert_id:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.false_positive_reported = True

        db.commit()
        db.refresh(report)
        logger.info(f"False positive report submitted for {entity} by user {reported_by}")
        return report

    @staticmethod
    def apply_override(
        db: Session,
        report_id: uuid_lib.UUID,
        reviewer_id: uuid_lib.UUID,
        notes: str = "",
    ) -> Any:
        """
        Confirm a false positive report and apply override:
          1. Mark report as confirmed
          2. Resolve any active block on the entity
          3. Update associated alert
        """
        from src.models.models import FalsePositiveReport, BlockedEntity, Alert

        report = db.query(FalsePositiveReport).filter(
            FalsePositiveReport.id == report_id
        ).first()
        if not report:
            raise ValueError(f"FalsePositiveReport {report_id} not found")

        report.status = "confirmed"
        report.reviewed_by = reviewer_id
        report.reviewer_notes = notes
        report.override_applied = True
        report.reviewed_at = datetime.utcnow()

        # Resolve any active blocks on this entity
        now = datetime.utcnow()
        active_blocks = db.query(BlockedEntity).filter(
            and_(
                BlockedEntity.workspace_id == report.workspace_id,
                BlockedEntity.entity == report.entity,
                BlockedEntity.resolved_status == False,
                BlockedEntity.blocked_until > now,
            )
        ).all()
        for block in active_blocks:
            block.resolved_status = True
            block.unblocked_at = now
            block.unblocked_by = reviewer_id

        # Update alert if linked
        if report.alert_id:
            alert = db.query(Alert).filter(Alert.id == report.alert_id).first()
            if alert:
                alert.in_review_queue = False

        db.commit()
        logger.info(f"FP override applied for {report.entity} by reviewer {reviewer_id}")
        return report

    @staticmethod
    def reject_report(
        db: Session,
        report_id: uuid_lib.UUID,
        reviewer_id: uuid_lib.UUID,
        notes: str = "",
    ) -> Any:
        """Reject a false positive report (entity remains blocked)."""
        from src.models.models import FalsePositiveReport
        report = db.query(FalsePositiveReport).filter(
            FalsePositiveReport.id == report_id
        ).first()
        if not report:
            raise ValueError(f"FalsePositiveReport {report_id} not found")

        report.status = "rejected"
        report.reviewed_by = reviewer_id
        report.reviewer_notes = notes
        report.reviewed_at = datetime.utcnow()
        db.commit()
        return report

    @staticmethod
    def get_fp_metrics(db: Session, workspace_id: uuid_lib.UUID) -> Dict[str, Any]:
        """Return false positive statistics for a workspace."""
        from src.models.models import FalsePositiveReport, HumanReviewQueue

        total = db.query(FalsePositiveReport).filter(
            FalsePositiveReport.workspace_id == workspace_id
        ).count()
        confirmed = db.query(FalsePositiveReport).filter(
            and_(
                FalsePositiveReport.workspace_id == workspace_id,
                FalsePositiveReport.status == "confirmed",
            )
        ).count()
        pending = db.query(FalsePositiveReport).filter(
            and_(
                FalsePositiveReport.workspace_id == workspace_id,
                FalsePositiveReport.status == "pending",
            )
        ).count()
        review_queue_pending = db.query(HumanReviewQueue).filter(
            and_(
                HumanReviewQueue.workspace_id == workspace_id,
                HumanReviewQueue.status == "pending",
            )
        ).count()

        fp_rate = round(confirmed / total, 4) if total > 0 else 0.0

        return {
            "total_reports": total,
            "confirmed_fp": confirmed,
            "pending_reports": pending,
            "fp_rate": fp_rate,
            "review_queue_pending": review_queue_pending,
        }

    @staticmethod
    def get_review_queue(
        db: Session,
        workspace_id: uuid_lib.UUID,
        status: str = "pending",
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List, int]:
        """Return paginated human review queue items."""
        from src.models.models import HumanReviewQueue
        query = db.query(HumanReviewQueue).filter(
            and_(
                HumanReviewQueue.workspace_id == workspace_id,
                HumanReviewQueue.status == status,
            )
        )
        total = query.count()
        items = query.order_by(HumanReviewQueue.created_at.desc()).offset(skip).limit(limit).all()
        return items, total

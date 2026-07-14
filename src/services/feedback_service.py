from datetime import datetime, timezone
import uuid
import csv
import os
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException

from src.models.models import AIFeedback, ScanHistory, AuditLog


class FeedbackService:
    @staticmethod
    def submit_feedback(
        db: Session,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID,
        scan_id: uuid.UUID,
        feedback_type: str,
        comments: Optional[str] = None
    ) -> AIFeedback:
        # Verify the scan exists and belongs to the workspace
        scan = db.query(ScanHistory).filter(
            ScanHistory.id == scan_id,
            ScanHistory.workspace_id == workspace_id
        ).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Create feedback
        feedback = AIFeedback(
            workspace_id=workspace_id,
            scan_id=scan_id,
            user_id=user_id,
            entity=scan.entity,
            entity_type=scan.input_type,
            predicted_label=scan.verdict,
            actual_label="safe" if feedback_type == "false_positive" else "malicious",
            confidence=scan.ml_confidence,
            risk_score=scan.risk_score,
            feedback_type=feedback_type,
            comments=comments,
            review_status="pending"
        )
        db.add(feedback)
        
        # Log action
        log = AuditLog(
            workspace_id=workspace_id,
            user_id=user_id,
            action="feedback_submitted",
            module="feedback",
            details={"scan_id": str(scan_id), "feedback_type": feedback_type}
        )
        db.add(log)
        
        db.commit()
        db.refresh(feedback)
        return feedback

    @staticmethod
    def get_feedback(
        db: Session,
        workspace_id: uuid.UUID,
        status: Optional[str] = None,
        limit: int = 100,
        skip: int = 0
    ) -> List[AIFeedback]:
        query = db.query(AIFeedback).filter(AIFeedback.workspace_id == workspace_id)
        if status:
            query = query.filter(AIFeedback.review_status == status)
        
        return query.order_by(AIFeedback.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def get_stats(db: Session, workspace_id: uuid.UUID) -> Dict:
        base_query = db.query(AIFeedback).filter(AIFeedback.workspace_id == workspace_id)
        
        total = base_query.count()
        pending = base_query.filter(AIFeedback.review_status == "pending").count()
        approved = base_query.filter(AIFeedback.review_status == "approved").count()
        rejected = base_query.filter(AIFeedback.review_status == "rejected").count()
        
        false_positives = base_query.filter(AIFeedback.feedback_type == "false_positive").count()
        false_negatives = base_query.filter(AIFeedback.feedback_type == "false_negative").count()
        correct = base_query.filter(AIFeedback.feedback_type == "correct").count()
        
        approval_rate = (approved / (approved + rejected) * 100) if (approved + rejected) > 0 else 0
        
        return {
            "total": total,
            "pending": pending,
            "approved": approved,
            "rejected": rejected,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "correct": correct,
            "approval_rate": round(approval_rate, 2)
        }

    @staticmethod
    def approve_feedback(
        db: Session,
        workspace_id: uuid.UUID,
        feedback_id: uuid.UUID,
        user_id: uuid.UUID
    ) -> AIFeedback:
        feedback = db.query(AIFeedback).filter(
            AIFeedback.id == feedback_id,
            AIFeedback.workspace_id == workspace_id
        ).first()

        if not feedback:
            raise HTTPException(status_code=404, detail="Feedback not found")
            
        if feedback.review_status != "pending":
            raise HTTPException(status_code=400, detail=f"Feedback is already {feedback.review_status}")

        feedback.review_status = "approved"
        feedback.approved_by = user_id
        feedback.approved_at = datetime.now(timezone.utc)
        
        # Export to dataset
        FeedbackService._export_to_csv(feedback)

        # Log action
        log = AuditLog(
            workspace_id=workspace_id,
            user_id=user_id,
            action="feedback_approved",
            module="feedback",
            details={"feedback_id": str(feedback_id)}
        )
        db.add(log)
        
        db.commit()
        db.refresh(feedback)
        return feedback

    @staticmethod
    def reject_feedback(
        db: Session,
        workspace_id: uuid.UUID,
        feedback_id: uuid.UUID,
        user_id: uuid.UUID
    ) -> AIFeedback:
        feedback = db.query(AIFeedback).filter(
            AIFeedback.id == feedback_id,
            AIFeedback.workspace_id == workspace_id
        ).first()

        if not feedback:
            raise HTTPException(status_code=404, detail="Feedback not found")
            
        if feedback.review_status != "pending":
            raise HTTPException(status_code=400, detail=f"Feedback is already {feedback.review_status}")

        feedback.review_status = "rejected"
        
        # Log action
        log = AuditLog(
            workspace_id=workspace_id,
            user_id=user_id,
            action="feedback_rejected",
            module="feedback",
            details={"feedback_id": str(feedback_id)}
        )
        db.add(log)
        
        db.commit()
        db.refresh(feedback)
        return feedback

    @staticmethod
    def _export_to_csv(feedback: AIFeedback):
        """Append approved feedback to the offline retraining dataset"""
        dataset_path = "datasets/feedback_dataset.csv"
        file_exists = os.path.isfile(dataset_path)
        
        os.makedirs("datasets", exist_ok=True)
        
        with open(dataset_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                # Write header
                writer.writerow([
                    "id",
                    "original_input",
                    "entity_type",
                    "predicted_label",
                    "correct_label",
                    "confidence",
                    "risk_score",
                    "feedback_type",
                    "timestamp"
                ])
                
            writer.writerow([
                str(feedback.id),
                feedback.entity,
                feedback.entity_type,
                feedback.predicted_label,
                feedback.actual_label,
                feedback.confidence,
                feedback.risk_score,
                feedback.feedback_type,
                feedback.approved_at.isoformat() if feedback.approved_at else ""
            ])

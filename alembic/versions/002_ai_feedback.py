"""Add human-in-the-loop AI feedback storage.

Revision ID: 002_ai_feedback
Revises: 001_initial_schema
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002_ai_feedback"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "ai_feedback",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_history.id"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("entity", sa.String()), sa.Column("entity_type", sa.String()),
        sa.Column("predicted_label", sa.String()), sa.Column("actual_label", sa.String()),
        sa.Column("confidence", sa.Float()), sa.Column("risk_score", sa.Integer()),
        sa.Column("feedback_type", sa.String()), sa.Column("comments", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("review_status", sa.String(), server_default="pending"),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_aifeedback_workspace_created", "ai_feedback", ["workspace_id", "created_at"])
    op.create_index("ix_aifeedback_workspace_status", "ai_feedback", ["workspace_id", "review_status"])

def downgrade():
    op.drop_index("ix_aifeedback_workspace_status", table_name="ai_feedback")
    op.drop_index("ix_aifeedback_workspace_created", table_name="ai_feedback")
    op.drop_table("ai_feedback")

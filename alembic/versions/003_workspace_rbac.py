"""Add workspace membership roles.

Revision ID: 003_workspace_rbac
Revises: 002_ai_feedback
"""

from alembic import op
import sqlalchemy as sa


revision = "003_workspace_rbac"
down_revision = "002_ai_feedback"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workspace_users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("invited_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("joined_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("uq_workspace_user_membership", "workspace_users", ["workspace_id", "user_id"], unique=True)
    op.create_index("ix_workspace_users_workspace_role", "workspace_users", ["workspace_id", "role"])


def downgrade() -> None:
    op.drop_index("ix_workspace_users_workspace_role", table_name="workspace_users")
    op.drop_index("uq_workspace_user_membership", table_name="workspace_users")
    op.drop_table("workspace_users")

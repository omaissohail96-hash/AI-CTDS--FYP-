"""Add login tracking fields to users.

Revision ID: 004_login_tracking
Revises: 003_workspace_rbac
"""

from alembic import op
import sqlalchemy as sa


revision = "004_login_tracking"
down_revision = "003_workspace_rbac"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("last_login_ip", sa.String(), nullable=True))
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("login_count", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("users", "login_count")
    op.drop_column("users", "last_login_at")
    op.drop_column("users", "last_login_ip")

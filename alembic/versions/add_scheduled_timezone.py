"""add scheduled_timezone column to notifications

Revision ID: add_scheduled_timezone
Revises: fix_incidentstatus_enum
Create Date: 2026-03-12
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "add_scheduled_timezone"
down_revision = "fix_incidentstatus_enum"
branch_labels = None
depends_on = None


def column_exists(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns(table_name)]
    return column_name in columns


def upgrade() -> None:

    if not column_exists("notifications", "scheduled_timezone"):
        op.add_column(
            "notifications",
            sa.Column("scheduled_timezone", sa.String(100), nullable=True),
        )


def downgrade() -> None:

    if column_exists("notifications", "scheduled_timezone"):
        op.drop_column("notifications", "scheduled_timezone")
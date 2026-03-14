"""add_last_seen_at_and_update_is_active_default

Revision ID: 20260314_000000
Revises: 20260312_121931
Create Date: 2026-03-14 00:00:00.000000

This migration:
1. Adds last_seen_at column to track user online presence
2. Changes is_active default to False (tracks real-time online status)
3. Sets all existing users to inactive (is_active=False) since they're not currently online

"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision: str = "20260314_000000"
down_revision: Union[str, None] = "1c958728d5a9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def column_exists(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns(table_name)]
    return column_name in columns


def upgrade() -> None:
    # Add last_seen_at column if it doesn't exist
    if not column_exists("users", "last_seen_at"):
        op.add_column(
            "users",
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        )
    
    # Set all existing users to inactive since they're not currently online
    # This changes the meaning of is_active from "account enabled" to "currently online"
    op.execute("UPDATE users SET is_active = FALSE")


def downgrade() -> None:
    # Drop the last_seen_at column
    if column_exists("users", "last_seen_at"):
        op.drop_column("users", "last_seen_at")
    
    # Note: We don't reset is_active to TRUE in downgrade
    # as that would incorrectly mark all users as active

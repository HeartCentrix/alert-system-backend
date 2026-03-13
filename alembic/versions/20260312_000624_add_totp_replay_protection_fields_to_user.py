"""add_totp_replay_protection_fields_to_user

Revision ID: 20260312_000624
Revises: fix_delivery_logs_fk_cascade, expand_mfa_secret_column
Create Date: 2026-03-12 00:06:24.000000
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision: str = "20260312_000624"
down_revision: Union[str, None] = ("fix_delivery_logs_fk_cascade", "expand_mfa_secret_column")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def column_exists(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns(table_name)]
    return column_name in columns


def upgrade() -> None:

    if not column_exists("users", "last_used_totp_code"):
        op.add_column(
            "users",
            sa.Column("last_used_totp_code", sa.String(6), nullable=True),
        )

    if not column_exists("users", "last_used_totp_at"):
        op.add_column(
            "users",
            sa.Column("last_used_totp_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:

    if column_exists("users", "last_used_totp_at"):
        op.drop_column("users", "last_used_totp_at")

    if column_exists("users", "last_used_totp_code"):
        op.drop_column("users", "last_used_totp_code")
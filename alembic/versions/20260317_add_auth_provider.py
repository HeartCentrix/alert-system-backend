"""empty migration - placeholder for 20260317_add_auth_provider

This is a placeholder migration to fix the alembic_version table
which was referencing a non-existent migration.

Revision ID: 20260317_add_auth_provider
Revises: 20260315_000000
Create Date: 2026-03-17 00:00:00.000000
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "20260317_add_auth_provider"
down_revision: Union[str, None] = "20260315_000000"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # This is a placeholder - no actual changes
    pass


def downgrade() -> None:
    # This is a placeholder - no actual changes
    pass

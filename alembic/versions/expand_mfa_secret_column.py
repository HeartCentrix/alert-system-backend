"""expand mfa_secret column for Fernet encryption

Revision ID: expand_mfa_secret_column
Revises: ensure_all_columns_exist
Create Date: 2026-03-11

This migration expands the mfa_secret column from 32 to 255 characters
to accommodate Fernet-encrypted secrets (typically ~120+ characters).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'expand_mfa_secret_column'
down_revision = 'ensure_all_columns_exist'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Expand mfa_secret column to support Fernet-encrypted secrets."""
    # Alter the mfa_secret column in users table
    op.alter_column(
        'users',
        'mfa_secret',
        existing_type=sa.String(32),
        type_=sa.String(255),
        existing_nullable=True
    )


def downgrade() -> None:
    """Revert mfa_secret column to original size (WARNING: may truncate data)."""
    # Note: This may truncate encrypted secrets if users have enrolled with encryption
    # Only run this if you're sure no encrypted secrets exist
    op.alter_column(
        'users',
        'mfa_secret',
        existing_type=sa.String(255),
        type_=sa.String(32),
        existing_nullable=True
    )

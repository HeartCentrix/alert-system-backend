"""add token_valid_after column for session invalidation

Revision ID: add_token_valid_after_column
Revises: expand_mfa_secret_column
Create Date: 2026-03-11

This migration adds the token_valid_after column to the users table
to support session invalidation when users change their password.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_token_valid_after_column'
down_revision = 'expand_mfa_secret_column'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add token_valid_after column to users table."""
    # Check if column already exists (for safety)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns('users')]
    
    if 'token_valid_after' in columns:
        print("Column token_valid_after already exists, skipping...")
        return
    
    # Add the column
    op.add_column(
        'users',
        sa.Column('token_valid_after', sa.TIMESTAMP(timezone=True), nullable=True)
    )
    
    # Create index for faster lookups during token validation
    op.create_index(
        'ix_users_token_valid_after',
        'users',
        ['token_valid_after'],
        unique=False
    )


def downgrade() -> None:
    """Remove token_valid_after column from users table."""
    op.drop_index('ix_users_token_valid_after', table_name='users')
    op.drop_column('users', 'token_valid_after')

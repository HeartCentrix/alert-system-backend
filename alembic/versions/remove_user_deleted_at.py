"""remove deleted_at column from users table

Revision ID: remove_user_deleted_at
Revises: location_audience_v1
Create Date: 2026-03-09

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'remove_user_deleted_at'
down_revision = 'location_audience_v1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Remove the deleted_at column from users table.
    
    This migration converts from soft deletion to hard deletion.
    All users will be permanently deleted instead of marked as deleted.
    """
    # Drop the deleted_at column
    op.drop_column('users', 'deleted_at')


def downgrade() -> None:
    """Re-add the deleted_at column for rollback.
    
    Note: Downgrade does not restore any deleted data.
    """
    op.add_column('users', sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True))

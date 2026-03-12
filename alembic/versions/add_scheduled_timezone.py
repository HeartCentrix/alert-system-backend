"""add scheduled_timezone column to notifications

Revision ID: add_scheduled_timezone
Revises: fix_incidentstatus_enum
Create Date: 2026-03-12

Add scheduled_timezone column to store the original timezone
when a notification is scheduled (e.g., "America/New_York", "Asia/Kolkata").
The scheduled_at is always stored in UTC in the database.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_scheduled_timezone'
down_revision = 'fix_incidentstatus_enum'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add scheduled_timezone column to notifications table."""
    op.add_column('notifications', sa.Column('scheduled_timezone', sa.String(100), nullable=True))


def downgrade() -> None:
    """Remove scheduled_timezone column from notifications table."""
    op.drop_column('notifications', 'scheduled_timezone')

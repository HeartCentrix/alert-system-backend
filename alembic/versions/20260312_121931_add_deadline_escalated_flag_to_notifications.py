"""add_deadline_escalated_flag_to_notifications

Revision ID: add_deadline_escalated
Revises: previous_revision
Create Date: 2026-03-12 12:19:31.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_deadline_escalated'
down_revision = None  # Will be updated automatically
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add deadline_escalated column to notifications table."""
    # Check if column already exists (for idempotency)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns('notifications')]
    
    if 'deadline_escalated' not in columns:
        op.add_column('notifications', sa.Column('deadline_escalated', sa.Boolean(), nullable=True, default=False))
        # Set default value for existing rows
        op.execute("UPDATE notifications SET deadline_escalated = FALSE WHERE deadline_escalated IS NULL")
        # Set not null constraint after populating
        op.alter_column('notifications', 'deadline_escalated', nullable=False, server_default='false')
    else:
        print("Column 'deadline_escalated' already exists, skipping")


def downgrade() -> None:
    """Remove deadline_escalated column from notifications table."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns('notifications')]
    
    if 'deadline_escalated' in columns:
        op.drop_column('notifications', 'deadline_escalated')
    else:
        print("Column 'deadline_escalated' does not exist, skipping downgrade")

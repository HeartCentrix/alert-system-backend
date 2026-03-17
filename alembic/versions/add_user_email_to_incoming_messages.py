"""add user_email to incoming_messages

Revision ID: add_user_email_incoming
Revises: fix_audit_logs_fk
Create Date: 2026-03-10

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_user_email_incoming'
down_revision = 'fix_audit_logs_fk'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add user_email column to incoming_messages table if it doesn't exist."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    incoming_messages_columns = [col['name'] for col in inspector.get_columns('incoming_messages')]
    if 'user_email' not in incoming_messages_columns:
        op.add_column('incoming_messages', sa.Column('user_email', sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column('incoming_messages', 'user_email')

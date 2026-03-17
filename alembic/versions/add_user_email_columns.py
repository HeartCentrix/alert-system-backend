"""add user_email to delivery_logs and notification_responses

Revision ID: add_user_email_columns
Revises: remove_user_deleted_at
Create Date: 2026-03-09

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = 'add_user_email_columns'
down_revision = 'remove_user_deleted_at'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Check if user_email column already exists in delivery_logs
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    # Add user_email to delivery_logs if it doesn't exist
    delivery_logs_columns = [col['name'] for col in inspector.get_columns('delivery_logs')]
    if 'user_email' not in delivery_logs_columns:
        op.add_column('delivery_logs', sa.Column('user_email', sa.String(255), nullable=True))
    
    # Add user_email to notification_responses if it doesn't exist
    notification_responses_columns = [col['name'] for col in inspector.get_columns('notification_responses')]
    if 'user_email' not in notification_responses_columns:
        op.add_column('notification_responses', sa.Column('user_email', sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column('notification_responses', 'user_email')
    op.drop_column('delivery_logs', 'user_email')

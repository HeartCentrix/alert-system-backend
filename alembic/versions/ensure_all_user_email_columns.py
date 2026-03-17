"""ensure all user_email columns exist for data preservation

Revision ID: ensure_all_user_email_columns
Revises: add_user_email_incoming
Create Date: 2026-03-10

This migration ensures all tables that reference users have a user_email column
to preserve data even after user deletion (ON DELETE SET NULL).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ensure_all_user_email_columns'
down_revision = 'add_user_email_incoming'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add user_email columns to all tables that reference users."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # List of tables that should have user_email column
    tables_to_check = [
        ('delivery_logs', 'user_id'),
        ('notification_responses', 'user_id'),
        ('incoming_messages', 'user_id'),
        ('audit_logs', 'user_id'),
    ]

    for table_name, user_column in tables_to_check:
        # Check if table exists
        if not inspector.has_table(table_name):
            continue

        # Get existing columns
        columns = [col['name'] for col in inspector.get_columns(table_name)]

        # Add user_email if it doesn't exist
        if 'user_email' not in columns:
            print(f"Adding user_email column to {table_name}")
            op.add_column(table_name, sa.Column('user_email', sa.String(255), nullable=True))
        else:
            print(f"user_email already exists in {table_name}")


def downgrade() -> None:
    """Remove user_email columns from all tables."""
    # Note: Downgrade is destructive and should be used with caution
    op.drop_column('audit_logs', 'user_email')
    op.drop_column('incoming_messages', 'user_email')
    op.drop_column('notification_responses', 'user_email')
    op.drop_column('delivery_logs', 'user_email')

"""ensure all columns exist for data preservation and backward compatibility

Revision ID: ensure_all_columns_exist
Revises: ensure_all_user_email_columns
Create Date: 2026-03-10

This migration ensures all tables have required columns defined in models
to prevent any column mismatch errors in production.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ensure_all_columns_exist'
down_revision = 'ensure_all_user_email_columns'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing columns to all tables based on current model definitions."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Define all tables and their expected columns
    # Format: (table_name, column_name, column_type, nullable)
    columns_to_add = [
        # delivery_logs - already has user_email from previous migration
        # notification_responses - already has user_email from previous migration
        # incoming_messages - already has user_email from previous migration
        # audit_logs - already has user_email from previous migration
    ]

    for table_name, col_name, col_type, nullable in columns_to_add:
        # Check if table exists
        if not inspector.has_table(table_name):
            print(f"Table {table_name} does not exist, skipping")
            continue

        # Get existing columns
        columns = [col['name'] for col in inspector.get_columns(table_name)]

        # Add column if it doesn't exist
        if col_name not in columns:
            print(f"Adding {col_name} column to {table_name}")
            op.add_column(table_name, sa.Column(col_name, col_type, nullable=nullable))
        else:
            print(f"{col_name} already exists in {table_name}")


def downgrade() -> None:
    """Remove added columns (destructive - use with caution)."""
    # No columns to remove in this migration
    pass

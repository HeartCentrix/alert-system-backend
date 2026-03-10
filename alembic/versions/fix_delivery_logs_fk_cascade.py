"""fix delivery_logs user_id foreign key to use ON DELETE CASCADE

Revision ID: fix_delivery_logs_fk_cascade
Revises: ensure_all_user_email_columns
Create Date: 2026-03-10

This migration fixes the IntegrityError that occurs when deleting users.
The delivery_logs.user_id foreign key is changed from ON DELETE SET NULL to ON DELETE CASCADE,
so that dependent delivery_logs rows are deleted automatically when a user is hard-deleted,
instead of attempting to set user_id to NULL which violates the NOT NULL constraint.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fix_delivery_logs_fk_cascade'
down_revision = 'ensure_all_user_email_columns'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Change delivery_logs.user_id FK to use ON DELETE CASCADE."""
    conn = op.get_bind()

    # Drop the existing foreign key constraint
    # Note: PostgreSQL creates FK constraints with naming convention: {table}_{column}_fkey
    op.drop_constraint('delivery_logs_user_id_fkey', 'delivery_logs', type_='foreignkey')

    # Recreate with ON DELETE CASCADE
    op.create_foreign_key(
        'delivery_logs_user_id_fkey',
        'delivery_logs',
        'users',
        ['user_id'],
        ['id'],
        ondelete='CASCADE'
    )

    # Also fix notification_responses for consistency
    op.drop_constraint('notification_responses_user_id_fkey', 'notification_responses', type_='foreignkey')
    op.create_foreign_key(
        'notification_responses_user_id_fkey',
        'notification_responses',
        'users',
        ['user_id'],
        ['id'],
        ondelete='CASCADE'
    )

    # Also fix incoming_messages for consistency
    op.drop_constraint('incoming_messages_user_id_fkey', 'incoming_messages', type_='foreignkey')
    op.create_foreign_key(
        'incoming_messages_user_id_fkey',
        'incoming_messages',
        'users',
        ['user_id'],
        ['id'],
        ondelete='CASCADE'
    )


def downgrade() -> None:
    """Revert to ON DELETE SET NULL."""
    conn = op.get_bind()

    # Revert delivery_logs
    op.drop_constraint('delivery_logs_user_id_fkey', 'delivery_logs', type_='foreignkey')
    op.create_foreign_key(
        'delivery_logs_user_id_fkey',
        'delivery_logs',
        'users',
        ['user_id'],
        ['id'],
        ondelete='SET NULL'
    )

    # Revert notification_responses
    op.drop_constraint('notification_responses_user_id_fkey', 'notification_responses', type_='foreignkey')
    op.create_foreign_key(
        'notification_responses_user_id_fkey',
        'notification_responses',
        'users',
        ['user_id'],
        ['id'],
        ondelete='SET NULL'
    )

    # Revert incoming_messages
    op.drop_constraint('incoming_messages_user_id_fkey', 'incoming_messages', type_='foreignkey')
    op.create_foreign_key(
        'incoming_messages_user_id_fkey',
        'incoming_messages',
        'users',
        ['user_id'],
        ['id'],
        ondelete='SET NULL'
    )

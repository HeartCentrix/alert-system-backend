"""add unique constraint to delivery_logs to prevent duplicate entries

Revision ID: 20260315_000000
Revises: 20260314_000000
Create Date: 2026-03-15 00:00:00.000000

Adds a unique constraint on (notification_id, user_id, channel) to prevent
duplicate delivery log entries for the same recipient/channel combination.
Removes any existing duplicates before applying the constraint.
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "20260315_000000"
down_revision: Union[str, None] = "20260314_000000"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove duplicate delivery logs before adding constraint
    # Keep only the log with the lowest id (earliest created) for each duplicate set
    op.execute("""
        DELETE FROM delivery_logs
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM delivery_logs
            GROUP BY notification_id, user_id, channel
        )
    """)

    op.create_unique_constraint(
        'uq_delivery_log_notification_user_channel',
        'delivery_logs',
        ['notification_id', 'user_id', 'channel']
    )


def downgrade() -> None:
    op.drop_constraint(
        'uq_delivery_log_notification_user_channel',
        'delivery_logs',
        type_='unique'
    )

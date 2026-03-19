"""add unique constraint to user_locations

Revision ID: 20260319_203000
Revises: location_audience_v1
Create Date: 2026-03-19 20:30:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.exc import ProgrammingError


# revision identifiers, used by Alembic.
revision: str = '20260319_203000'
down_revision: Union[str, None] = 'location_audience_v1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Clean up any existing duplicates first (keep oldest)
    try:
        op.execute("""
            DELETE FROM user_locations
            WHERE id NOT IN (
                SELECT min_id
                FROM (
                    SELECT MIN(id) as min_id
                    FROM user_locations
                    GROUP BY user_id, location_id, status
                ) AS keep
            )
        """)
    except Exception as e:
        # Table might not exist yet or already clean
        pass
    
    # Add the unique constraint (IF NOT EXISTS for PostgreSQL 9.5+)
    try:
        op.create_unique_constraint(
            'uq_user_location_active',
            'user_locations',
            ['user_id', 'location_id', 'status']
        )
    except ProgrammingError as e:
        # Constraint might already exist
        if 'already exists' not in str(e).lower():
            raise


def downgrade() -> None:
    # Remove the unique constraint
    try:
        op.drop_constraint('uq_user_location_active', 'user_locations', type_='unique')
    except Exception:
        # Constraint might not exist
        pass

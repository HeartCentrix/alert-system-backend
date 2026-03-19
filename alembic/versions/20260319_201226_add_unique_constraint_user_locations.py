"""add unique constraint to user_locations

Revision ID: {datetime.now().strftime('%Y%m%d%H%M%S')}
Revises: location_audience_v1
Create Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '{datetime.now().strftime('%Y%m%d%H%M%S')}'
down_revision: Union[str, None] = 'location_audience_v1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add unique constraint to prevent duplicate active assignments
    # First, clean up any existing duplicates (keep the oldest)
    op.execute("""
        DELETE FROM user_locations
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM user_locations
            GROUP BY user_id, location_id, status
        )
    """)
    
    # Create the unique constraint
    op.create_unique_constraint(
        'uq_user_location_active',
        'user_locations',
        ['user_id', 'location_id', 'status']
    )


def downgrade() -> None:
    # Remove the unique constraint
    op.drop_constraint('uq_user_location_active', 'user_locations', type_='unique')

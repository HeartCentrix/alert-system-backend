"""merge migration heads

Revision ID: 1c958728d5a9
Revises: 20260312_121931, add_scheduled_timezone
Create Date: 2026-03-13 17:41:59.866145
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1c958728d5a9'
down_revision = ('20260312_121931', 'add_scheduled_timezone')
branch_labels = None
depends_on = None

def upgrade():
    # This is a merge migration — no schema changes needed.
    # Merges heads: 20260312_121931 and add_scheduled_timezone.
    pass


def downgrade():
    # Merge migrations have no downgrade operation.
    pass
"""add user_email column to audit_logs

Revision ID: add_audit_log_user_email
Revises: location_audience_v1
Create Date: 2026-03-09

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_audit_log_user_email'
down_revision = 'location_audience_v1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('audit_logs', sa.Column('user_email', sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column('audit_logs', 'user_email')

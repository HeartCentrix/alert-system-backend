"""add sms opt-in columns to users

Revision ID: add_sms_opt_in_columns
Revises: expand_mfa_secret_column
Create Date: 2026-06-12

Adds the SMS text-alert opt-in decision captured by the first-login popup:
- sms_opt_in: NULL = not asked yet, True = accepted, False = declined
- sms_opt_in_at: when the decision was recorded (consent audit trail)
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_sms_opt_in_columns'
down_revision = 'expand_mfa_secret_column'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('sms_opt_in', sa.Boolean(), nullable=True))
    op.add_column('users', sa.Column('sms_opt_in_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'sms_opt_in_at')
    op.drop_column('users', 'sms_opt_in')

"""fix audit_logs user_id foreign key to use ON DELETE SET NULL

Revision ID: fix_audit_logs_fk
Revises: add_user_email_columns
Create Date: 2026-03-09

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fix_audit_logs_fk'
down_revision = 'add_user_email_columns'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    
    # Drop the existing foreign key constraint
    op.drop_constraint('audit_logs_user_id_fkey', 'audit_logs', type_='foreignkey')
    
    # Recreate with ON DELETE SET NULL
    op.create_foreign_key(
        'audit_logs_user_id_fkey',
        'audit_logs',
        'users',
        ['user_id'],
        ['id'],
        ondelete='SET NULL'
    )


def downgrade() -> None:
    conn = op.get_bind()
    
    # Drop the constraint with SET NULL
    op.drop_constraint('audit_logs_user_id_fkey', 'audit_logs', type_='foreignkey')
    
    # Recreate without explicit ondelete (default behavior)
    op.create_foreign_key(
        'audit_logs_user_id_fkey',
        'audit_logs',
        'users',
        ['user_id'],
        ['id']
    )

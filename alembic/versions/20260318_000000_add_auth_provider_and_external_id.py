"""add auth_provider and external_id to users

Revision ID: 20260318_000000
Revises: 20260315_000000
Create Date: 2026-03-18 00:00:00.000000

Adds authentication provider support for SSO integration:
- auth_provider column: "local", "entra", or "ldap"
- external_id column: Entra OID or LDAP DN (unique, indexed)
- Makes hashed_password nullable for SSO users
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "20260318_000000"
down_revision: Union[str, None] = "20260317_add_auth_provider"  # Points to placeholder migration
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Check if columns already exist before adding them
    from sqlalchemy.engine import reflection
    from alembic import op
    import sqlalchemy as sa
    
    conn = op.get_bind()
    inspector = reflection.Inspector.from_engine(conn)
    columns = [col['name'] for col in inspector.get_columns('users')]
    
    # Add auth_provider column with default value "local"
    if 'auth_provider' not in columns:
        op.add_column(
            'users',
            sa.Column('auth_provider', sa.String(20), nullable=False, server_default='local')
        )
    
    # Add external_id column for storing Entra OID or LDAP DN
    if 'external_id' not in columns:
        op.add_column(
            'users',
            sa.Column('external_id', sa.String(255), nullable=True)
        )
        
        # Create index on external_id for fast lookups
        op.create_index('ix_users_external_id', 'users', ['external_id'], unique=True)
    
    # Make hashed_password nullable for SSO users who don't have local passwords
    # Check current nullable status
    user_columns = {col['name']: col for col in inspector.get_columns('users')}
    if 'hashed_password' in user_columns and not user_columns['hashed_password']['nullable']:
        op.alter_column('users', 'hashed_password', existing_type=sa.String(255), nullable=True)


def downgrade() -> None:
    # Drop index on external_id
    op.drop_index('ix_users_external_id', table_name='users')

    # Remove external_id column
    op.drop_column('users', 'external_id')

    # Remove auth_provider column
    op.drop_column('users', 'auth_provider')

    # Restore hashed_password to NOT NULL (may fail if SSO users exist)
    op.alter_column('users', 'hashed_password', existing_type=sa.String(255), nullable=False)

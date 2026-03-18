"""add is_enabled and is_online columns

Revision ID: 20260318_000002
Revises: 20260318_000000
Create Date: 2026-03-18 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260318_000002'
down_revision = '20260318_000000'
branch_labels = None
depends_on = None


def upgrade():
    # Check if columns already exist
    from sqlalchemy import inspect
    from app.database import engine
    
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns('users')]
    
    # Add is_enabled column (account status - admin controlled)
    if 'is_enabled' not in columns:
        op.add_column('users', sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='true'))
    else:
        print("Column 'is_enabled' already exists")
    
    # Add is_online column (real-time presence via heartbeat)
    if 'is_online' not in columns:
        op.add_column('users', sa.Column('is_online', sa.Boolean(), nullable=False, server_default='false'))
    else:
        print("Column 'is_online' already exists")
    
    # Migrate existing is_active values to is_online (if is_active exists)
    if 'is_active' in columns and 'is_online' in columns:
        op.execute("""
            UPDATE users 
            SET is_online = is_active 
            WHERE is_active IS NOT NULL
        """)
    
    # Set is_enabled based on account status
    # For now, all existing users are enabled (not deleted/disabled)
    if 'is_enabled' in columns:
        op.execute("""
            UPDATE users 
            SET is_enabled = true
        """)
    
    # Note: We keep is_active column for backward compatibility during transition
    # Future migrations can remove it once all code is updated


def downgrade():
    # Remove the new columns
    op.drop_column('users', 'is_online')
    op.drop_column('users', 'is_enabled')
    
    # Note: is_active remains unchanged from its original state

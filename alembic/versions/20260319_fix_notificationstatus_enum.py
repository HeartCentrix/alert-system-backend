"""fix notificationstatus enum values

Revision ID: 20260319_fix_notificationstatus_enum
Revises: 001_create_enum_types
Create Date: 2026-03-19 00:00:00.000000

Add missing notification status enum values that were defined in models
but not added to the database enum type.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20260319_fix_notificationstatus_enum'
down_revision = '001_create_enum_types'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing notification status enum values."""
    conn = op.get_bind()
    
    # Get current enum values
    result = conn.execute(sa.text("""
        SELECT e.enumlabel 
        FROM pg_type t 
        JOIN pg_enum e ON t.oid = e.enumtypid  
        WHERE t.typname = 'notificationstatus'
        ORDER BY e.enumsortorder
    """))
    current_values = [row[0] for row in result.fetchall()]
    
    # Required values
    required_values = ['draft', 'sending', 'sent', 'partially_sent', 'failed', 'scheduled', 'cancelled']
    
    # Add missing values
    for value in required_values:
        if value not in current_values:
            try:
                conn.execute(sa.text(f"ALTER TYPE notificationstatus ADD VALUE '{value}'"))
                print(f"Added '{value}' to notificationstatus enum")
            except Exception as e:
                print(f"Could not add '{value}': {e}")
    
    print("notificationstatus enum updated successfully")


def downgrade() -> None:
    """Cannot remove enum values in PostgreSQL without recreating the type."""
    pass

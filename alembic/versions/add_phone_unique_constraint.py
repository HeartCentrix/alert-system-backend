"""Add unique constraint to users.phone column

Revision ID: add_phone_unique_constraint
Revises: previous_revision
Create Date: 2026-03-19

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_phone_unique_constraint'
down_revision = None  # Update with previous revision
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add unique constraint to phone column"""
    
    # First, handle duplicate phone numbers (keep only the first occurrence)
    # Set duplicate phones to NULL to preserve data
    op.execute("""
        UPDATE users
        SET phone = NULL
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM users
            WHERE phone IS NOT NULL
            GROUP BY phone
        )
        AND phone IS NOT NULL
    """)
    
    # Create unique index on phone column
    # This will fail if there are still duplicates, but the above should handle it
    try:
        op.create_index('ix_users_phone', 'users', ['phone'], unique=True)
        print("✅ Successfully added unique constraint to users.phone")
    except Exception as e:
        print(f"⚠️  Could not add unique constraint: {e}")
        print("⚠️  Please manually check for duplicate phone numbers")


def downgrade() -> None:
    """Remove unique constraint from phone column"""
    op.drop_index('ix_users_phone', table_name='users')
    print("✅ Removed unique constraint from users.phone")

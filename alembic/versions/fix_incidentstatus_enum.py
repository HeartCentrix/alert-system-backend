"""fix incidentstatus and incidentseverity enums to use lowercase values

Revision ID: fix_incidentstatus_enum
Revises: 20260312_000624
Create Date: 2026-03-12

This migration fixes the incidentstatus enum to use lowercase values
(active, monitoring, resolved, cancelled) instead of uppercase (ACTIVE, MONITORING, RESOLVED).
It also adds the missing CANCELLED value.

Additionally fixes incidentseverity enum from uppercase (HIGH, MEDIUM, LOW, INFO)
to lowercase (high, medium, low, info).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fix_incidentstatus_enum'
down_revision = '20260312_000624'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Update incidentstatus and incidentseverity enums to use lowercase values."""
    conn = op.get_bind()

    # === FIX INCIDENTSTATUS ENUM ===
    # Step 1: Add the new 'CANCELLED' value to the existing uppercase enum
    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (
                SELECT oid FROM pg_type WHERE typname = 'incidentstatus'
            )
            AND enumlabel = 'CANCELLED'
        )
    """)).scalar()

    if not result:
        conn.execute(sa.text("""
            ALTER TYPE incidentstatus ADD VALUE IF NOT EXISTS 'CANCELLED' AFTER 'RESOLVED'
        """))

    # Step 2: Rename uppercase values to lowercase (only if old value exists)
    # This prevents crashes when re-running migrations on a fresh database
    
    # Check and rename ACTIVE -> active
    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'incidentstatus')
            AND enumlabel = 'ACTIVE'
        )
    """)).scalar()
    if result:
        conn.execute(sa.text("ALTER TYPE incidentstatus RENAME VALUE 'ACTIVE' TO 'active'"))

    # Check and rename MONITORING -> monitoring
    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'incidentstatus')
            AND enumlabel = 'MONITORING'
        )
    """)).scalar()
    if result:
        conn.execute(sa.text("ALTER TYPE incidentstatus RENAME VALUE 'MONITORING' TO 'monitoring'"))

    # Check and rename RESOLVED -> resolved
    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'incidentstatus')
            AND enumlabel = 'RESOLVED'
        )
    """)).scalar()
    if result:
        conn.execute(sa.text("ALTER TYPE incidentstatus RENAME VALUE 'RESOLVED' TO 'resolved'"))

    # Check and rename CANCELLED -> cancelled
    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'incidentstatus')
            AND enumlabel = 'CANCELLED'
        )
    """)).scalar()
    if result:
        conn.execute(sa.text("ALTER TYPE incidentstatus RENAME VALUE 'CANCELLED' TO 'cancelled'"))

    # === FIX INCIDENTSEVERITY ENUM ===
    # Check and rename each value only if it exists
    
    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'incidentseverity')
            AND enumlabel = 'HIGH'
        )
    """)).scalar()
    if result:
        conn.execute(sa.text("ALTER TYPE incidentseverity RENAME VALUE 'HIGH' TO 'high'"))

    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'incidentseverity')
            AND enumlabel = 'MEDIUM'
        )
    """)).scalar()
    if result:
        conn.execute(sa.text("ALTER TYPE incidentseverity RENAME VALUE 'MEDIUM' TO 'medium'"))

    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'incidentseverity')
            AND enumlabel = 'LOW'
        )
    """)).scalar()
    if result:
        conn.execute(sa.text("ALTER TYPE incidentseverity RENAME VALUE 'LOW' TO 'low'"))

    result = conn.execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'incidentseverity')
            AND enumlabel = 'INFO'
        )
    """)).scalar()
    if result:
        conn.execute(sa.text("ALTER TYPE incidentseverity RENAME VALUE 'INFO' TO 'info'"))


def downgrade() -> None:
    """Revert enum values to uppercase."""
    conn = op.get_bind()
    
    # Revert incidentstatus enum
    conn.execute(sa.text("""
        ALTER TYPE incidentstatus RENAME VALUE 'active' TO 'ACTIVE'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentstatus RENAME VALUE 'monitoring' TO 'MONITORING'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentstatus RENAME VALUE 'resolved' TO 'RESOLVED'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentstatus RENAME VALUE 'cancelled' TO 'CANCELLED'
    """))
    
    # Revert incidentseverity enum
    conn.execute(sa.text("""
        ALTER TYPE incidentseverity RENAME VALUE 'high' TO 'HIGH'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentseverity RENAME VALUE 'medium' TO 'MEDIUM'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentseverity RENAME VALUE 'low' TO 'LOW'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentseverity RENAME VALUE 'info' TO 'INFO'
    """))

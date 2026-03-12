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
    
    # Step 2: Rename uppercase values to lowercase
    conn.execute(sa.text("""
        ALTER TYPE incidentstatus RENAME VALUE 'ACTIVE' TO 'active'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentstatus RENAME VALUE 'MONITORING' TO 'monitoring'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentstatus RENAME VALUE 'RESOLVED' TO 'resolved'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentstatus RENAME VALUE 'CANCELLED' TO 'cancelled'
    """))
    
    # === FIX INCIDENTSEVERITY ENUM ===
    # Rename uppercase values to lowercase
    conn.execute(sa.text("""
        ALTER TYPE incidentseverity RENAME VALUE 'HIGH' TO 'high'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentseverity RENAME VALUE 'MEDIUM' TO 'medium'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentseverity RENAME VALUE 'LOW' TO 'low'
    """))
    
    conn.execute(sa.text("""
        ALTER TYPE incidentseverity RENAME VALUE 'INFO' TO 'info'
    """))


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

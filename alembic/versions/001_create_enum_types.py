"""create all required PostgreSQL ENUM types

Revision ID: 001_create_enum_types
Revises: 
Create Date: 2026-03-04 00:00:00.000000

This migration creates all ENUM types required by the application
before any tables are created.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001_create_enum_types'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all ENUM types if they don't exist."""
    conn = op.get_bind()
    
    # User roles
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS userrole AS ENUM ('super_admin', 'admin', 'manager', 'viewer')"))
    
    # Group types
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS grouptype AS ENUM ('static', 'dynamic')"))
    
    # Notification status
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS notificationstatus AS ENUM ('draft', 'sending', 'sent', 'partially_sent', 'failed', 'scheduled', 'cancelled')"))
    
    # Delivery status
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS deliverystatus AS ENUM ('pending', 'sent', 'delivered', 'failed', 'bounced')"))
    
    # Response types
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS responsetype AS ENUM ('safe', 'need_help', 'acknowledged', 'custom')"))
    
    # Alert channels
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS alertchannel AS ENUM ('sms', 'email', 'voice', 'slack', 'teams', 'web')"))
    
    # Incident severity
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS incidentseverity AS ENUM ('high', 'medium', 'low', 'info')"))
    
    # Incident status
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS incidentstatus AS ENUM ('active', 'monitoring', 'resolved', 'cancelled')"))
    
    # User location assignment types
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS userlocationassignmenttype AS ENUM ('manual', 'geofence')"))
    
    # User location status
    conn.execute(sa.text("CREATE TYPE IF NOT EXISTS userlocationstatus AS ENUM ('active', 'inactive')"))


def downgrade() -> None:
    """Drop all ENUM types."""
    conn = op.get_bind()
    
    # Note: This will fail if any tables still reference these types
    # Tables must be dropped first
    conn.execute(sa.text("DROP TYPE IF EXISTS userlocationstatus"))
    conn.execute(sa.text("DROP TYPE IF EXISTS userlocationassignmenttype"))
    conn.execute(sa.text("DROP TYPE IF EXISTS incidentstatus"))
    conn.execute(sa.text("DROP TYPE IF EXISTS incidentseverity"))
    conn.execute(sa.text("DROP TYPE IF EXISTS alertchannel"))
    conn.execute(sa.text("DROP TYPE IF EXISTS responsetype"))
    conn.execute(sa.text("DROP TYPE IF EXISTS deliverystatus"))
    conn.execute(sa.text("DROP TYPE IF EXISTS notificationstatus"))
    conn.execute(sa.text("DROP TYPE IF EXISTS grouptype"))
    conn.execute(sa.text("DROP TYPE IF EXISTS userrole"))

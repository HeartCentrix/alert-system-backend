#!/usr/bin/env python3
"""
Create PostgreSQL ENUM types required by the application.

This script creates all the ENUM types that SQLAlchemy models reference.
Run this once to fix "type does not exist" errors.
"""
import sys
from sqlalchemy import create_engine, text
from app.database import engine


ENUM_TYPES = [
    ("userrole", ["super_admin", "admin", "manager", "viewer"]),
    ("grouptype", ["static", "dynamic"]),
    ("notificationstatus", ["draft", "sending", "sent", "partially_sent", "failed", "scheduled", "cancelled"]),
    ("deliverystatus", ["pending", "sent", "delivered", "failed", "bounced"]),
    ("responsetype", ["safe", "need_help", "acknowledged", "custom"]),
    ("alertchannel", ["sms", "email", "voice", "slack", "teams", "web"]),
    ("incidentseverity", ["high", "medium", "low", "info"]),
    ("incidentstatus", ["active", "monitoring", "resolved", "cancelled"]),
    ("userlocationassignmenttype", ["manual", "geofence"]),
    ("userlocationstatus", ["active", "inactive"]),
]


def create_enum_types():
    """Create all ENUM types if they don't exist."""
    with engine.connect() as conn:
        for enum_name, values in ENUM_TYPES:
            # Check if type exists
            result = conn.execute(
                text("SELECT EXISTS(SELECT 1 FROM pg_type WHERE typname = :name)"),
                {"name": enum_name}
            ).scalar()
            
            if result:
                print(f"✓ ENUM type '{enum_name}' already exists")
            else:
                # Create enum type
                values_str = ", ".join(f"'{v}'" for v in values)
                sql = f"CREATE TYPE {enum_name} AS ENUM ({values_str})"
                conn.execute(text(sql))
                conn.commit()
                print(f"✓ Created ENUM type '{enum_name}'")


def main():
    print("=" * 70)
    print("Creating PostgreSQL ENUM Types")
    print("=" * 70)
    print()
    
    try:
        create_enum_types()
        print()
        print("=" * 70)
        print("All ENUM types created successfully!")
        print("=" * 70)
        return 0
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())

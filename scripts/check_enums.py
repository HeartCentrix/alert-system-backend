#!/usr/bin/env python3
"""Check which PostgreSQL ENUM types exist and which are missing."""
import sys
from sqlalchemy import create_engine, text
from app.database import engine


REQUIRED_ENUMS = [
    "userrole",
    "grouptype", 
    "notificationstatus",
    "deliverystatus",
    "responsetype",
    "alertchannel",
    "incidentseverity",
    "incidentstatus",
    "userlocationassignmenttype",
    "userlocationstatus",
]


def check_enums():
    """Check which ENUM types exist."""
    with engine.connect() as conn:
        existing = []
        missing = []
        
        for enum_name in REQUIRED_ENUMS:
            result = conn.execute(
                text("SELECT EXISTS(SELECT 1 FROM pg_type WHERE typname = :name)"),
                {"name": enum_name}
            ).scalar()
            
            if result:
                existing.append(enum_name)
                print(f"✓ {enum_name}")
            else:
                missing.append(enum_name)
                print(f"✗ {enum_name} - MISSING")
        
        return existing, missing


def main():
    print("=" * 70)
    print("Checking PostgreSQL ENUM Types")
    print("=" * 70)
    print()
    
    existing, missing = check_enums()
    
    print()
    print("=" * 70)
    print(f"Existing: {len(existing)} | Missing: {len(missing)}")
    print("=" * 70)
    
    if missing:
        print(f"\nMissing enums: {', '.join(missing)}")
    
    return 0 if not missing else 1


if __name__ == '__main__':
    sys.exit(main())

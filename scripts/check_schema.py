#!/usr/bin/env python3
"""
Pre-deployment Database Schema Check

This script validates that all database columns defined in models
exist in the database. It exits with code 1 if there are missing columns.

Usage in CI/CD:
    python scripts/check_schema.py
    
Returns:
    0 - Schema is valid
    1 - Schema has issues (missing columns/tables)
"""
import sys
from sqlalchemy import inspect, create_engine
from app.database import Base, engine
from app.models import (
    User, Group, Location, Notification, NotificationTemplate,
    Incident, DeliveryLog, NotificationResponse, IncomingMessage,
    AuditLog, RefreshToken, LocationAutocompleteCache
)


def get_model_columns():
    """Extract column names from all SQLAlchemy models."""
    columns_by_table = {}
    for model in Base.registry.mappers:
        table_name = model.local_table.name
        columns_by_table[table_name] = {col.name for col in model.local_table.columns}
    return columns_by_table


def get_database_columns(inspector):
    """Extract column names from the database."""
    columns_by_table = {}
    for table_name in inspector.get_table_names():
        if table_name == 'alembic_version':
            continue
        columns_by_table[table_name] = {col['name'] for col in inspector.get_columns(table_name)}
    return columns_by_table


def check_schema():
    """Check if all model columns exist in database."""
    inspector = inspect(engine)
    
    model_columns = get_model_columns()
    db_columns = get_database_columns(inspector)
    
    missing_columns = []
    missing_tables = []
    
    for table_name, model_cols in model_columns.items():
        if table_name not in db_columns:
            missing_tables.append(table_name)
            continue
        
        missing = model_cols - db_columns[table_name]
        if missing:
            for col in missing:
                missing_columns.append(f"{table_name}.{col}")
    
    if missing_tables:
        print("❌ MISSING TABLES:")
        for table in missing_tables:
            print(f"   - {table}")
        print()
    
    if missing_columns:
        print("❌ MISSING COLUMNS:")
        for col in missing_columns:
            print(f"   - {col}")
        print()
    
    if missing_tables or missing_columns:
        print("⚠️  Run migrations: alembic upgrade head")
        print("⚠️  Or run: python scripts/validate_db_schema.py --fix")
        return False
    
    print("✅ Database schema is valid - all columns exist")
    return True


if __name__ == '__main__':
    success = check_schema()
    sys.exit(0 if success else 1)

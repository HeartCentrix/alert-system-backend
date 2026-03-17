#!/usr/bin/env python3
"""
Database Schema Validator and Auto-Fix Script

This script compares the current database schema against SQLAlchemy models
and generates SQL statements to add missing columns or create missing tables.

Usage:
    python scripts/validate_db_schema.py [--fix]

Options:
    --fix    Apply the fixes to the database (dry-run by default)
"""
import sys
from sqlalchemy import inspect, create_engine, text
from sqlalchemy.schema import CreateTable
from app.database import Base, engine
from app.models import (
    User, Group, Location, Notification, NotificationTemplate,
    Incident, DeliveryLog, NotificationResponse, IncomingMessage,
    AuditLog, RefreshToken
)


def get_model_columns():
    """Extract column definitions from all SQLAlchemy models."""
    columns_by_table = {}
    for model in Base.registry.mappers:
        table_name = model.local_table.name
        columns = []
        for col in model.local_table.columns:
            columns.append({
                'name': col.name,
                'type': col.type,
                'nullable': col.nullable,
                'default': col.default,
                'server_default': col.server_default,
            })
        columns_by_table[table_name] = columns
    return columns_by_table


def get_database_columns(inspector):
    """Extract column definitions from the database."""
    columns_by_table = {}
    for table_name in inspector.get_table_names():
        if table_name == 'alembic_version':
            continue
        columns = []
        for col in inspector.get_columns(table_name):
            columns.append({
                'name': col['name'],
                'type': col['type'],
                'nullable': col['nullable'],
                'default': col['default'],
            })
        columns_by_table[table_name] = columns
    return columns_by_table


def validate_schema():
    """Compare model schema with database schema and report differences."""
    inspector = inspect(engine)
    
    model_columns = get_model_columns()
    db_columns = get_database_columns(inspector)
    
    issues = []
    
    # Check for missing tables
    for table_name in model_columns:
        if table_name not in db_columns:
            issues.append({
                'type': 'missing_table',
                'table': table_name,
                'message': f"Table '{table_name}' is missing from database"
            })
            continue
        
        # Check for missing columns
        model_col_names = {col['name'] for col in model_columns[table_name]}
        db_col_names = {col['name'] for col in db_columns[table_name]}
        
        missing_cols = model_col_names - db_col_names
        for col_name in missing_cols:
            col_def = next(c for c in model_columns[table_name] if c['name'] == col_name)
            issues.append({
                'type': 'missing_column',
                'table': table_name,
                'column': col_name,
                'definition': col_def,
                'message': f"Column '{col_name}' is missing from table '{table_name}'"
            })
        
        # Check for extra columns in database (not in models)
        extra_cols = db_col_names - model_col_names
        for col_name in extra_cols:
            issues.append({
                'type': 'extra_column',
                'table': table_name,
                'column': col_name,
                'message': f"Column '{col_name}' exists in database but not in models for table '{table_name}'"
            })
    
    return issues


def generate_fix_sql(issues):
    """Generate SQL statements to fix schema issues."""
    sql_statements = []
    
    for issue in issues:
        if issue['type'] == 'missing_table':
            # Find the model for this table
            for model in Base.registry.mappers:
                if model.local_table.name == issue['table']:
                    create_stmt = str(CreateTable(model.local_table).compile(engine))
                    sql_statements.append(f"-- Create table {issue['table']}")
                    sql_statements.append(create_stmt + ";")
                    break
        
        elif issue['type'] == 'missing_column':
            col = issue['definition']
            type_str = col['type'].compile(dialect=engine.dialect)
            nullable_str = "NULL" if col['nullable'] else "NOT NULL"
            default_str = ""
            
            if col['server_default'] is not None:
                default_str = f" DEFAULT {col['server_default'].arg}"
            elif col['default'] is not None and hasattr(col['default'], 'arg'):
                default_str = f" DEFAULT {col['default'].arg}"
            
            # sql = f"ALTER TABLE {issue['table']} ADD COLUMN {col['name']} {type_str} {nullable_str}{default_str};"
            sql = f"ALTER TABLE {issue['table']} ADD COLUMN IF NOT EXISTS {col['name']} {type_str} {nullable_str}{default_str};"
            sql_statements.append(f"-- {issue['message']}")
            sql_statements.append(sql)
        
        elif issue['type'] == 'extra_column':
            sql_statements.append(f"-- {issue['message']}")
            sql_statements.append(f"-- Consider removing: ALTER TABLE {issue['table']} DROP COLUMN {issue['column']};")
    
    return sql_statements


def apply_fixes(issues):
    """Apply schema fixes to the database."""
    sql_statements = generate_fix_sql(issues)
    
    if not sql_statements:
        print("No fixes needed!")
        return True
    
    print(f"\nApplying {len(sql_statements)} fix(es) to the database...")
    
    with engine.connect() as conn:
        for sql in sql_statements:
            if sql.startswith('--'):
                print(f"  {sql}")
                continue
            
            print(f"  Executing: {sql}")
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception as e:
                print(f"  ERROR: {e}")
                conn.rollback()
                return False
    
    print("\nAll fixes applied successfully!")
    return True


def main():
    apply_fix = '--fix' in sys.argv
    
    print("=" * 70)
    print("Database Schema Validator")
    print("=" * 70)
    
    issues = validate_schema()
    
    if not issues:
        print("\n✅ Database schema matches models perfectly!")
        return 0
    
    print(f"\n⚠️  Found {len(issues)} schema issue(s):\n")
    for issue in issues:
        print(f"  • {issue['message']}")
    
    if apply_fix:
        print("\n" + "=" * 70)
        print("Applying fixes...")
        print("=" * 70)
        success = apply_fixes(issues)
        return 0 if success else 1
    else:
        print("\n" + "=" * 70)
        print("Run with --fix flag to apply these changes")
        print("Or use 'alembic revision --autogenerate' to create a migration")
        print("=" * 70)
        
        # Show SQL that would be executed
        print("\nProposed SQL:")
        for sql in generate_fix_sql(issues):
            print(f"  {sql}")
        
        return 1


if __name__ == '__main__':
    sys.exit(main())

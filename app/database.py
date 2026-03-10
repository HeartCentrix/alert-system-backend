from sqlalchemy import create_engine, text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Railway provides postgresql:// but SQLAlchemy needs postgresql+psycopg2://
db_url = settings.DATABASE_URL
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

# Enforce TLS for database connections in production.
# - "require": connection fails if SSL is unavailable (no silent plaintext fallback)
# - Skipped in development where local PostgreSQL typically has no SSL cert
# - Railway PostgreSQL supports SSL, so this works out of the box there
_connect_args = {}
if settings.APP_ENV != "development":
    _connect_args["sslmode"] = "require"
    logger.info("Database SSL enforced (sslmode=require)")

engine = create_engine(
    db_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    connect_args=_connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_column_exists(table_name: str, column_name: str, column_type: str, nullable: bool = True):
    """
    Check if a column exists in a table, and create it if it doesn't.
    
    Args:
        table_name: Name of the table to check
        column_name: Name of the column to check/create
        column_type: SQL column type (e.g., 'DOUBLE PRECISION', 'VARCHAR(255)', 'TIMESTAMP WITH TIME ZONE')
        nullable: Whether the column allows NULL values
    
    Returns:
        bool: True if column was created, False if it already existed
    """
    db = SessionLocal()
    try:
        # Check if column exists
        result = db.execute(
            text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = :table_name 
                AND column_name = :column_name
            """),
            {"table_name": table_name, "column_name": column_name}
        ).fetchone()
        
        if result:
            logger.info(f"Column '{column_name}' already exists in table '{table_name}'")
            return False
        
        # Column doesn't exist, create it
        null_constraint = "DROP NOT NULL" if nullable else "SET NOT NULL"
        db.execute(
            text(f"""
                ALTER TABLE {table_name} 
                ADD COLUMN {column_name} {column_type}
            """)
        )
        db.commit()
        logger.info(f"Created column '{column_name}' ({column_type}) in table '{table_name}'")
        return True
        
    except Exception as e:
        logger.error(f"Error ensuring column '{column_name}' in table '{table_name}': {e}")
        db.rollback()
        raise
    finally:
        db.close()


def ensure_table_exists(table_name: str):
    """
    Check if a table exists in the database.

    Args:
        table_name: Name of the table to check

    Returns:
        bool: True if table exists, False otherwise
    """
    db = SessionLocal()
    try:
        result = db.execute(
            text("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_name = :table_name
            """),
            {"table_name": table_name}
        ).fetchone()

        return result is not None

    except Exception as e:
        logger.error(f"Error checking table '{table_name}': {e}")
        return False
    finally:
        db.close()


def ensure_mfa_secret_column_expanded():
    """
    Ensure the mfa_secret column in users table is VARCHAR(255) for Fernet encryption.
    
    Fernet-encrypted secrets are ~120+ characters, but the original column was VARCHAR(32).
    This expands the column if it's still at the old size.
    
    Returns:
        bool: True if column was altered, False if already correct size
    """
    db = SessionLocal()
    try:
        # Check current column type
        result = db.execute(
            text("""
                SELECT character_maximum_length, data_type
                FROM information_schema.columns
                WHERE table_name = 'users'
                AND column_name = 'mfa_secret'
            """)
        ).fetchone()
        
        if not result:
            logger.error("mfa_secret column not found in users table")
            return False
        
        max_length, data_type = result
        
        # Check if already expanded to 255
        if max_length == 255:
            logger.info("mfa_secret column already expanded to VARCHAR(255)")
            return False
        
        # Expand the column
        db.execute(
            text("""
                ALTER TABLE users
                ALTER COLUMN mfa_secret TYPE VARCHAR(255)
            """)
        )
        db.commit()
        logger.info("Expanded mfa_secret column from VARCHAR(32) to VARCHAR(255)")
        return True
        
    except Exception as e:
        logger.error(f"Error expanding mfa_secret column: {e}")
        db.rollback()
        raise
    finally:
        db.close()

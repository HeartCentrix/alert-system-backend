from sqlalchemy import create_engine, text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings
import logging
import re

logger = logging.getLogger(__name__)

# Regex: identifiers must start with a letter or underscore,
# followed only by letters, digits, or underscores.
# This covers all valid PostgreSQL identifiers and blocks any injection attempt.
_SAFE_IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

# Allowed SQL column types — whitelist approach for column_type since it cannot
# be parameterized and has a much wider surface area than simple identifiers.
_ALLOWED_COLUMN_TYPES = {
    'DOUBLE PRECISION',
    'FLOAT',
    'INTEGER',
    'BIGINT',
    'SMALLINT',
    'BOOLEAN',
    'TEXT',
    'VARCHAR(255)',
    'VARCHAR(512)',
    'TIMESTAMP WITH TIME ZONE',
    'TIMESTAMP WITHOUT TIME ZONE',
    'DATE',
    'JSONB',
    'UUID',
}


def _validate_ddl_identifier(value: str, label: str) -> None:
    """
    Validate that a DDL identifier (table/column name) is safe for interpolation.
    Raises ValueError if the identifier contains anything other than
    letters, digits, and underscores, or starts with a digit.
    """
    if not _SAFE_IDENTIFIER_RE.match(value):
        raise ValueError(
            f"Invalid DDL identifier for {label}: '{value}'. "
            "Only letters, digits, and underscores are allowed."
        )


def _validate_column_type(column_type: str) -> None:
    """
    Validate column_type against an explicit allowlist.
    Raises ValueError if the type is not recognised.
    """
    if column_type.upper() not in {t.upper() for t in _ALLOWED_COLUMN_TYPES}:
        raise ValueError(
            f"Disallowed column type: '{column_type}'. "
            f"Allowed types: {sorted(_ALLOWED_COLUMN_TYPES)}"
        )


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
        table_name: Name of the table to check (letters, digits, underscores only)
        column_name: Name of the column to check/create (letters, digits, underscores only)
        column_type: SQL column type — must be on the approved allowlist
        nullable: Whether the column allows NULL values (default True)

    Returns:
        bool: True if column was created, False if it already existed

    Raises:
        ValueError: If table_name, column_name, or column_type fail validation
    """
    # --- Input validation: must happen before any DB interaction ---
    _validate_ddl_identifier(table_name, "table_name")
    _validate_ddl_identifier(column_name, "column_name")
    _validate_column_type(column_type)

    db = SessionLocal()
    try:
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

        # Build the DDL — safe because identifiers and type are validated above
        null_clause = "" if nullable else " NOT NULL"
        db.execute(
            text(f"""
                ALTER TABLE {table_name}
                ADD COLUMN {column_name} {column_type}{null_clause}
            """)
        )
        db.commit()
        logger.info(f"Created column '{column_name}' ({column_type}{null_clause}) in table '{table_name}'")
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

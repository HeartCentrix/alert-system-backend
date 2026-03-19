"""
Database initialization script.

Creates all tables and enums directly without requiring Alembic migrations.
This script is idempotent - safe to run multiple times.
"""
import logging
from sqlalchemy import text, inspect
from app.database import SessionLocal, engine, Base
# Import all models to ensure they're registered with Base
from app.models import (  # noqa: F401
    User, UserRole, Group, GroupType, Location, Notification, NotificationStatus,
    NotificationTemplate, Incident, IncidentStatus, IncidentSeverity, DeliveryLog,
    DeliveryStatus, NotificationResponse, ResponseType, IncomingMessage, AuditLog,
    RefreshToken, LoginAttempt, UserLocation, UserLocationHistory,
    UserLocationAssignmentType, UserLocationStatus, AlertChannel,
    group_members, notification_groups, notification_users,
)

logger = logging.getLogger(__name__)


def create_all_enums():
    """Create all PostgreSQL ENUM types if they don't exist."""
    logger.info("Creating ENUM types...")
    
    db = SessionLocal()
    try:
        conn = db.connection()
        
        # Helper function to check if enum exists and create it
        def create_enum_if_not_exists(enum_name, enum_values):
            # Check if enum type exists
            result = conn.execute(
                text("SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = :enum_name)"),
                {"enum_name": enum_name}
            ).scalar()
            
            if not result:
                values_str = ", ".join(f"'{v}'" for v in enum_values)
                conn.execute(text(f"CREATE TYPE {enum_name} AS ENUM ({values_str})"))
                logger.info(f"Created ENUM type: {enum_name}")
            else:
                logger.info(f"ENUM type already exists: {enum_name}")
        
        # User roles
        create_enum_if_not_exists("userrole", ["super_admin", "admin", "manager", "viewer"])
        
        # Group types
        create_enum_if_not_exists("grouptype", ["static", "dynamic"])

        # Notification status
        create_enum_if_not_exists("notificationstatus", ["draft", "sending", "sent", "partially_sent", "failed", "scheduled", "cancelled"])

        # Delivery status
        create_enum_if_not_exists("deliverystatus", ["pending", "sent", "delivered", "failed", "bounced"])

        # Response types
        create_enum_if_not_exists("responsetype", ["safe", "need_help", "acknowledged", "custom"])

        # Alert channels
        create_enum_if_not_exists("alertchannel", ["sms", "email", "voice", "slack", "teams", "web"])
        
        # Incident severity
        create_enum_if_not_exists("incidentseverity", ["high", "medium", "low", "info"])

        # Incident status
        create_enum_if_not_exists("incidentstatus", ["active", "monitoring", "resolved", "cancelled"])
        
        # User location assignment types
        create_enum_if_not_exists("userlocationassignmenttype", ["manual", "geofence"])

        # User location status
        create_enum_if_not_exists("userlocationstatus", ["active", "inactive"])
        
        db.commit()
        logger.info("All ENUM types created successfully")
        
    except Exception as e:
        logger.error(f"Error creating ENUM types: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def create_all_tables():
    """Create all database tables using SQLAlchemy Base.metadata.create_all()."""
    logger.info("Creating database tables...")

    try:
        # This creates all tables that inherit from Base
        # Tables are created in the correct order based on foreign key dependencies
        Base.metadata.create_all(bind=engine)
        logger.info("All database tables created successfully")
        
        # Ensure SSO-related columns exist (added in main branch)
        _ensure_sso_columns()

    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        raise


def _ensure_sso_columns():
    """
    Ensure SSO-related columns exist in the users table.
    
    These columns are required for Entra ID and LDAP authentication:
    - auth_provider: Authentication provider (local, entra, ldap)
    - external_id: External identity provider ID (Entra OID or LDAP DN)
    - is_enabled: Account enabled status (separate from is_online presence)
    - is_online: Real-time online presence indicator
    """
    db = SessionLocal()
    try:
        # Check and add auth_provider column
        result = db.execute(
            text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users'
                AND column_name = 'auth_provider'
            """)
        ).fetchone()
        
        if not result:
            db.execute(
                text("""
                    ALTER TABLE users
                    ADD COLUMN auth_provider VARCHAR(255) DEFAULT 'local' NOT NULL
                """)
            )
            logger.info("Added auth_provider column to users table")
        else:
            logger.info("Column auth_provider already exists")
        
        # Check and add external_id column
        result = db.execute(
            text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users'
                AND column_name = 'external_id'
            """)
        ).fetchone()
        
        if not result:
            db.execute(
                text("""
                    ALTER TABLE users
                    ADD COLUMN external_id VARCHAR(255)
                """)
            )
            logger.info("Added external_id column to users table")
        else:
            logger.info("Column external_id already exists")
        
        # Check and add is_enabled column
        result = db.execute(
            text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users'
                AND column_name = 'is_enabled'
            """)
        ).fetchone()
        
        if not result:
            db.execute(
                text("""
                    ALTER TABLE users
                    ADD COLUMN is_enabled BOOLEAN DEFAULT TRUE NOT NULL
                """)
            )
            logger.info("Added is_enabled column to users table")
        else:
            logger.info("Column is_enabled already exists")
        
        # Check and add is_online column
        result = db.execute(
            text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users'
                AND column_name = 'is_online'
            """)
        ).fetchone()
        
        if not result:
            db.execute(
                text("""
                    ALTER TABLE users
                    ADD COLUMN is_online BOOLEAN DEFAULT FALSE
                """)
            )
            logger.info("Added is_online column to users table")
        else:
            logger.info("Column is_online already exists")
        
        db.commit()
        
    except Exception as e:
        logger.error(f"Error ensuring SSO columns: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def verify_database():
    """Verify that all tables and enums were created correctly."""
    logger.info("Verifying database schema...")
    
    db = SessionLocal()
    try:
        # Get list of all tables
        result = db.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_type = 'BASE TABLE'
            ORDER BY table_name
        """))
        tables = [row[0] for row in result.fetchall()]
        
        expected_tables = {
            'users', 'locations', 'groups', 'notification_templates',
            'incidents', 'notifications', 'delivery_logs', 'notification_responses',
            'incoming_messages', 'audit_logs', 'refresh_tokens', 'login_attempts',
            'user_locations', 'user_location_history', 'mfa_recovery_codes',
            # Association tables
            'group_members', 'notification_groups', 'notification_users'
        }
        
        missing_tables = expected_tables - set(tables)
        if missing_tables:
            logger.warning(f"Missing tables: {missing_tables}")
        else:
            logger.info(f"All {len(expected_tables)} tables verified successfully")
        
        # Verify ENUM types
        result = db.execute(text("""
            SELECT t.typname as enum_name
            FROM pg_type t
            JOIN pg_enum e ON t.oid = e.enumtypid
            JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname = 'public'
            GROUP BY t.typname
            ORDER BY t.typname
        """))
        enums = [row[0] for row in result.fetchall()]
        
        expected_enums = {
            'userrole', 'grouptype', 'notificationstatus', 'deliverystatus',
            'responsetype', 'alertchannel', 'incidentseverity', 'incidentstatus',
            'userlocationassignmenttype', 'userlocationstatus'
        }
        
        missing_enums = expected_enums - set(enums)
        if missing_enums:
            logger.warning(f"Missing ENUM types: {missing_enums}")
        else:
            logger.info(f"All {len(expected_enums)} ENUM types verified successfully")
        
        return len(missing_tables) == 0 and len(missing_enums) == 0
        
    except Exception as e:
        logger.error(f"Error verifying database: {e}")
        return False
    finally:
        db.close()


def init_db():
    """
    Initialize the database by creating all enums and tables.
    
    This function is idempotent - safe to call multiple times.
    """
    logger.info("=" * 50)
    logger.info("Initializing database...")
    logger.info("=" * 50)
    
    try:
        # Step 1: Create ENUM types
        create_all_enums()
        
        # Step 2: Create all tables
        create_all_tables()
        
        # Step 3: Verify the database
        success = verify_database()
        
        if success:
            logger.info("=" * 50)
            logger.info("Database initialization completed successfully!")
            logger.info("=" * 50)
        else:
            logger.warning("Database initialization completed with warnings")
            
        return success
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        init_db()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        sys.exit(1)

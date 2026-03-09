"""
Pytest Conftest - Shared Fixtures and Configuration

This module provides shared fixtures for all tests including:
- Database session management
- Test user creation
- Authentication tokens
- Redis mock
- Celery mock
- API test client
"""
import os
import pytest
import asyncio
from typing import Generator, Optional, AsyncGenerator
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, MagicMock, AsyncMock, patch

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, get_db
from app.models import User, UserRole, Location, Group, Notification, Incident, NotificationStatus
from app.core.security import hash_password, create_access_token, create_refresh_token
from app.config import settings

# =============================================================================
# DATABASE FIXTURES
# =============================================================================

# Test database URL - uses isolated test database
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/tm_alert_test"
)


@pytest.fixture(scope="session")
def test_engine():
    """
    Create a test database engine.
    
    For unit tests, uses in-memory SQLite.
    For integration tests, uses PostgreSQL test database.
    """
    # Check if we should use PostgreSQL or SQLite
    use_postgres = os.getenv("USE_POSTGRES_FOR_TESTS", "false").lower() == "true"
    
    if use_postgres:
        # PostgreSQL for integration tests
        engine = create_engine(
            TEST_DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://"),
            pool_pre_ping=True,
            echo=False
        )
    else:
        # SQLite for unit tests (faster, isolated)
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    yield engine
    
    # Cleanup
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_engine) -> Generator[Session, None, None]:
    """
    Create a fresh database session for each test.
    
    Uses transactions to rollback all changes after each test.
    """
    # Create a new connection
    connection = test_engine.connect()
    
    # Begin a transaction
    transaction = connection.begin()
    
    # Create a session bound to this connection
    SessionLocal = sessionmaker(
        bind=connection,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False
    )
    session = SessionLocal()
    
    # Patch the get_db dependency
    def override_get_db():
        try:
            yield session
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    
    yield session
    
    # Cleanup
    session.close()
    transaction.rollback()
    connection.close()
    
    # Remove the override
    app.dependency_overrides.clear()


@pytest.fixture
def clean_db(db_session: Session) -> Session:
    """
    Clean all data from the database before each test.
    
    Use this fixture when you need a completely clean database state.
    """
    # Delete all data in correct order (respecting foreign keys)
    for table in reversed(Base.metadata.sorted_tables):
        db_session.execute(table.delete())
    db_session.commit()
    
    yield db_session


# =============================================================================
# USER FIXTURES
# =============================================================================

@pytest.fixture
def test_user_data() -> dict:
    """Default test user data."""
    return {
        "email": "testuser@example.com",
        "password": "TestPassword123!",
        "first_name": "Test",
        "last_name": "User",
        "phone": "+1234567890",
        "role": UserRole.VIEWER,
    }


@pytest.fixture
def test_user(db_session: Session, test_user_data: dict) -> User:
    """Create a test user in the database."""
    user = User(
        email=test_user_data["email"],
        hashed_password=hash_password(test_user_data["password"]),
        first_name=test_user_data["first_name"],
        last_name=test_user_data["last_name"],
        phone=test_user_data.get("phone"),
        role=test_user_data.get("role", UserRole.VIEWER),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def admin_user(db_session: Session) -> User:
    """Create an admin user."""
    user = User(
        email="admin@example.com",
        hashed_password=hash_password("AdminPassword123!"),
        first_name="Admin",
        last_name="User",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def super_admin_user(db_session: Session) -> User:
    """Create a super admin user."""
    user = User(
        email="superadmin@example.com",
        hashed_password=hash_password("SuperAdminPassword123!"),
        first_name="Super",
        last_name="Admin",
        role=UserRole.SUPER_ADMIN,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def manager_user(db_session: Session) -> User:
    """Create a manager user."""
    user = User(
        email="manager@example.com",
        hashed_password=hash_password("ManagerPassword123!"),
        first_name="Manager",
        last_name="User",
        role=UserRole.MANAGER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def inactive_user(db_session: Session) -> User:
    """Create an inactive user."""
    user = User(
        email="inactive@example.com",
        hashed_password=hash_password("Password123!"),
        first_name="Inactive",
        last_name="User",
        role=UserRole.VIEWER,
        is_active=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# =============================================================================
# AUTHENTICATION FIXTURES
# =============================================================================

@pytest.fixture
def auth_tokens(test_user: User) -> dict:
    """Generate valid auth tokens for a test user."""
    access_token = create_access_token(
        data={"sub": str(test_user.id), "role": test_user.role.value}
    )
    refresh_token = create_refresh_token({"sub": str(test_user.id)})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@pytest.fixture
def admin_auth_tokens(admin_user: User) -> dict:
    """Generate valid auth tokens for an admin user."""
    access_token = create_access_token(
        data={"sub": str(admin_user.id), "role": admin_user.role.value}
    )
    refresh_token = create_refresh_token({"sub": str(admin_user.id)})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@pytest.fixture
def super_admin_auth_tokens(super_admin_user: User) -> dict:
    """Generate valid auth tokens for a super admin user."""
    access_token = create_access_token(
        data={"sub": str(super_admin_user.id), "role": super_admin_user.role.value}
    )
    refresh_token = create_refresh_token({"sub": str(super_admin_user.id)})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@pytest.fixture
def expired_token() -> str:
    """Generate an expired access token."""
    from app.core.security import ALGORITHM
    from jose import jwt
    
    payload = {
        "sub": "1",
        "role": "viewer",
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


@pytest.fixture
def invalid_token() -> str:
    """Return an invalid token string."""
    return "invalid.token.here"


@pytest.fixture
def tampered_token(auth_tokens: dict) -> str:
    """Return a tampered token (modified signature)."""
    parts = auth_tokens["access_token"].split(".")
    # Tamper with the signature
    return f"{parts[0]}.{parts[1]}.tampered_signature"


# =============================================================================
# API CLIENT FIXTURES
# =============================================================================

@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """
    Create a test client with database override.
    
    Use this for tests that need database access.
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def authenticated_client(client: TestClient, auth_tokens: dict) -> TestClient:
    """
    Create an authenticated test client.
    
    Use this for tests that require authentication.
    """
    client.headers.update({
        "Authorization": f"Bearer {auth_tokens['access_token']}"
    })
    return client


@pytest.fixture
def admin_client(client: TestClient, admin_auth_tokens: dict) -> TestClient:
    """Create an authenticated test client with admin privileges."""
    client.headers.update({
        "Authorization": f"Bearer {admin_auth_tokens['access_token']}"
    })
    return client


@pytest.fixture
def super_admin_client(client: TestClient, super_admin_auth_tokens: dict) -> TestClient:
    """Create an authenticated test client with super admin privileges."""
    client.headers.update({
        "Authorization": f"Bearer {super_admin_auth_tokens['access_token']}"
    })
    return client


# =============================================================================
# MODEL FIXTURES
# =============================================================================

@pytest.fixture
def test_location(db_session: Session) -> Location:
    """Create a test location."""
    location = Location(
        name="Test Office",
        address="123 Test Street",
        city="Test City",
        state="TS",
        zip_code="12345",
        country="USA",
        latitude=40.7128,
        longitude=-74.0060,
        geofence_radius_miles=5.0,
        is_active=True,
    )
    db_session.add(location)
    db_session.commit()
    db_session.refresh(location)
    return location


@pytest.fixture
def test_group(db_session: Session, test_user: User) -> Group:
    """Create a test group."""
    group = Group(
        name="Test Group",
        description="A test group for testing",
        type="static",
        is_active=True,
    )
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)
    
    # Add member
    group.members.append(test_user)
    db_session.commit()
    
    return group


@pytest.fixture
def test_incident(db_session: Session, test_user: User) -> Incident:
    """Create a test incident."""
    incident = Incident(
        title="Test Incident",
        type="weather",
        severity="high",
        status="active",
        description="This is a test incident",
        created_by_id=test_user.id,
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    return incident


@pytest.fixture
def test_notification(db_session: Session, test_user: User, test_incident: Incident) -> Notification:
    """Create a test notification."""
    notification = Notification(
        incident_id=test_incident.id,
        title="Test Notification",
        message="This is a test notification message",
        subject="Test Subject",
        channels=["sms", "email"],
        status=NotificationStatus.DRAFT,
        target_all=False,
        created_by_id=test_user.id,
    )
    db_session.add(notification)
    db_session.commit()
    db_session.refresh(notification)
    return notification


# =============================================================================
# REDIS FIXTURES
# =============================================================================

@pytest.fixture
def mock_redis() -> MagicMock:
    """Create a mock Redis client."""
    redis_mock = MagicMock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock(return_value=True)
    redis_mock.delete = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=True)
    redis_mock.zadd = AsyncMock(return_value=1)
    redis_mock.zrange = AsyncMock(return_value=[])
    redis_mock.georadius = AsyncMock(return_value=[])
    redis_mock.geodist = AsyncMock(return_value=None)
    redis_mock.geoadd = AsyncMock(return_value=1)
    redis_mock.close = AsyncMock()
    return redis_mock


@pytest.fixture
def redis_with_cache(mock_redis: MagicMock) -> Generator[MagicMock, None, None]:
    """
    Patch Redis in the application with a mock.
    
    Use this for tests that interact with Redis caching.
    """
    with patch("app.core.location_cache.redis", mock_redis):
        with patch("app.core.geofence.redis", mock_redis):
            yield mock_redis


# =============================================================================
# CELERY FIXTURES
# =============================================================================

@pytest.fixture
def mock_celery_task() -> MagicMock:
    """Create a mock Celery task."""
    task_mock = MagicMock()
    task_mock.delay = MagicMock()
    task_mock.apply_async = MagicMock()
    task_mock.retry = MagicMock()
    return task_mock


@pytest.fixture
def mock_celery() -> Generator[MagicMock, None, None]:
    """
    Patch Celery in the application with a mock.
    
    Use this for tests that trigger Celery tasks.
    """
    celery_mock = MagicMock()
    celery_mock.send_task = MagicMock()
    celery_mock.inspect = MagicMock()
    
    with patch("app.tasks.celery_app", celery_mock):
        with patch("app.celery_app.celery_app", celery_mock):
            yield celery_mock


# =============================================================================
# EXTERNAL SERVICE FIXTURES
# =============================================================================

@pytest.fixture
def mock_twilio() -> Generator[MagicMock, None, None]:
    """Mock Twilio service."""
    twilio_mock = MagicMock()
    twilio_mock.send_sms = MagicMock(return_value={"sid": "MOCK_SID", "status": "sent"})
    twilio_mock.make_voice_call = MagicMock(return_value={"sid": "MOCK_VOICE_SID", "status": "initiated"})

    with patch("app.tasks.twilio_service", twilio_mock):
        with patch("app.services.messaging.twilio_service", twilio_mock):
            yield twilio_mock


@pytest.fixture
def mock_email_service() -> Generator[MagicMock, None, None]:
    """Mock Email (SES) service."""
    email_mock = MagicMock()
    email_mock.send_email = MagicMock(return_value={"message_id": "MOCK_EMAIL_ID", "status": "sent"})
    email_mock.send_password_reset_email = MagicMock(return_value={"message_id": "MOCK_RESET_ID", "status": "sent"})
    email_mock.send_welcome_email = MagicMock(return_value={"message_id": "MOCK_WELCOME_ID", "status": "sent"})
    
    with patch("app.services.messaging.email_service", email_mock):
        yield email_mock


@pytest.fixture
def mock_webhook_service() -> Generator[MagicMock, None, None]:
    """Mock Webhook service (Slack/Teams)."""
    webhook_mock = MagicMock()
    webhook_mock.send_slack = MagicMock(return_value={"status": "sent"})
    webhook_mock.send_teams = MagicMock(return_value={"status": "sent"})
    
    with patch("app.services.messaging.webhook_service", webhook_mock):
        yield webhook_mock


@pytest.fixture
def mock_all_external_services(
    mock_twilio: MagicMock,
    mock_email_service: MagicMock,
    mock_webhook_service: MagicMock
) -> None:
    """Mock all external services at once."""
    pass  # Fixtures already handle the patching


# =============================================================================
# LOCATIONIQ FIXTURES
# =============================================================================

@pytest.fixture
def mock_locationiq_response() -> list:
    """Sample LocationIQ API response."""
    return [
        {
            "place_id": "123456",
            "display_name": "New York, NY, USA",
            "lat": "40.7128",
            "lon": "-74.0060",
            "type": "city",
            "importance": 0.9,
            "address": {
                "city": "New York",
                "state": "New York",
                "country": "United States",
                "country_code": "us",
            }
        },
        {
            "place_id": "789012",
            "display_name": "Newark, NJ, USA",
            "lat": "40.7357",
            "lon": "-74.1724",
            "type": "city",
            "importance": 0.7,
            "address": {
                "city": "Newark",
                "state": "New Jersey",
                "country": "United States",
                "country_code": "us",
            }
        }
    ]


# =============================================================================
# UTILITY FIXTURES
# =============================================================================

@pytest.fixture
def sample_coordinates() -> dict:
    """Sample coordinates for testing."""
    return {
        "nyc": {"lat": 40.7128, "lon": -74.0060},
        "la": {"lat": 34.0522, "lon": -118.2437},
        "chicago": {"lat": 41.8781, "lon": -87.6298},
        "london": {"lat": 51.5074, "lon": -0.1278},
        "paris": {"lat": 48.8566, "lon": 2.3522},
        "tokyo": {"lat": 35.6762, "lon": 139.6503},
    }


@pytest.fixture
def test_password() -> str:
    """Return a valid test password."""
    return "TestPassword123!"


@pytest.fixture
def weak_password() -> str:
    """Return a weak password (for validation tests)."""
    return "weak"


@pytest.fixture
def test_csv_content() -> str:
    """Sample CSV content for user import testing."""
    return """first_name,last_name,email,phone,department,title,employee_id,role
John,Doe,john.doe@example.com,+1234567890,Engineering,Developer,EMP001,viewer
Jane,Smith,jane.smith@example.com,+0987654321,Marketing,Manager,EMP002,manager
Bob,Johnson,bob.johnson@example.com,+1122334455,HR,Director,EMP003,admin"""


# =============================================================================
# ASYNC FIXTURES
# =============================================================================

@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# MARKER HELPERS
# =============================================================================

def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "api: API tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "slow: Slow tests")


# =============================================================================
# HOOKS
# =============================================================================

@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    """Run before test session starts."""
    print("\n" + "=" * 80)
    print("TM Alert Test Suite Starting...")
    print("=" * 80 + "\n")


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    """Run after test session finishes."""
    print("\n" + "=" * 80)
    print(f"Test Session Finished - Exit Status: {exitstatus}")
    print("=" * 80 + "\n")

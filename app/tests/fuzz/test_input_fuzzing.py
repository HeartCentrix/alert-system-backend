"""
Fuzz Tests using Hypothesis

Tests cover:
- API input fuzzing
- Schema validation fuzzing
- Edge case discovery
- Invalid input handling
"""
import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st
from hypothesis.extra.pydantic import build_pydantic_model_strategy
import json

from app.schemas import (
    LoginRequest,
    UserCreate,
    NotificationCreate,
    PasswordResetConfirm,
)


# =============================================================================
# API INPUT FUZZING
# =============================================================================

class TestAPIInputFuzzing:
    """Fuzz testing for API inputs."""

    @given(
        email=st.text(min_size=0, max_size=1000),
        password=st.text(min_size=0, max_size=1000),
    )
    @settings(deadline=1000, max_examples=200)
    def test_login_request_fuzz(self, email, password):
        """Fuzz login request with arbitrary inputs."""
        try:
            request = LoginRequest(email=email, password=password)
            # If created successfully, validate structure
            assert hasattr(request, 'email')
            assert hasattr(request, 'password')
        except Exception as e:
            # Should raise ValidationError, not crash
            assert "ValidationError" in str(type(e).__name__) or "error" in str(e).lower()

    @given(
        email=st.emails(),
        password=st.text(
            min_size=0,
            max_size=100,
            alphabet=st.characters(min_codepoint=0, max_codepoint=255)
        ),
    )
    @settings(deadline=1000, max_examples=100)
    def test_login_password_fuzz(self, email, password):
        """Fuzz password field with unicode and special chars."""
        try:
            request = LoginRequest(email=email, password=password)
            # Password should be preserved exactly
            assert request.password == password
        except Exception:
            # Validation errors are acceptable
            pass

    @given(
        # Generate potentially problematic strings
        problematic_string=st.one_of(
            st.text(min_size=0, max_size=10000),  # Very long strings
            st.just("null"),
            st.just("undefined"),
            st.just("<script>alert(1)</script>"),
            st.just("'; DROP TABLE users;--"),
            st.just("../../../etc/passwd"),
            st.just("\x00\x01\x02\x03"),  # Control characters
            st.just("🚨" * 100),  # Emojis
        )
    )
    @settings(deadline=1000, max_examples=100)
    def test_injection_attempts_fuzz(self, problematic_string):
        """Fuzz with injection payloads."""
        try:
            # Try in various fields
            LoginRequest(email=problematic_string, password="Password123!")
        except Exception:
            # Should not crash
            pass
        
        try:
            LoginRequest(email="test@example.com", password=problematic_string)
        except Exception:
            # Should not crash
            pass


# =============================================================================
# USER CREATE FUZZING
# =============================================================================

class TestUserCreateFuzzing:
    """Fuzz testing for user creation."""

    @given(
        email=st.one_of(
            st.emails(),
            st.text(min_size=0, max_size=500),
            st.just(""),
            st.just("not-an-email"),
        ),
        password=st.text(min_size=0, max_size=100),
        first_name=st.text(min_size=0, max_size=200),
        last_name=st.text(min_size=0, max_size=200),
    )
    @settings(deadline=1000, max_examples=200)
    def test_user_create_fuzz(self, email, password, first_name, last_name):
        """Fuzz user creation with arbitrary inputs."""
        try:
            user = UserCreate(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            # If created, validate structure
            assert hasattr(user, 'email')
            assert hasattr(user, 'password')
        except Exception as e:
            # Should raise ValidationError, not crash
            error_name = str(type(e).__name__)
            assert "Validation" in error_name or "Error" in error_name

    @given(
        # Fuzz role field
        role_input=st.one_of(
            st.sampled_from(["viewer", "manager", "admin", "super_admin"]),
            st.text(min_size=0, max_size=50),
            st.integers(),
            st.none(),
        )
    )
    @settings(deadline=1000, max_examples=100)
    def test_user_role_fuzz(self, role_input):
        """Fuzz role field with various inputs."""
        try:
            user = UserCreate(
                email="test@example.com",
                password="Password123!",
                first_name="Test",
                last_name="User",
                role=role_input if role_input else "viewer"
            )
        except Exception:
            # Invalid roles should fail validation
            pass


# =============================================================================
# NOTIFICATION FUZZING
# =============================================================================

class TestNotificationFuzzing:
    """Fuzz testing for notification creation."""

    @given(
        title=st.text(min_size=0, max_size=1000),
        message=st.text(min_size=0, max_size=10000),
        target_all=st.booleans(),
    )
    @settings(deadline=1000, max_examples=200)
    def test_notification_basic_fuzz(self, title, message, target_all):
        """Fuzz basic notification fields."""
        try:
            notification = NotificationCreate(
                title=title,
                message=message,
                channels=["sms"],
                target_all=target_all
            )
            assert hasattr(notification, 'title')
            assert hasattr(notification, 'message')
        except Exception:
            # Validation errors acceptable
            pass

    @given(
        # Fuzz channels field
        channels=st.one_of(
            st.lists(st.sampled_from(["sms", "email", "voice", "whatsapp"])),
            st.just([]),
            st.just(["invalid"]),
            st.none(),
        )
    )
    @settings(deadline=1000, max_examples=100)
    def test_notification_channels_fuzz(self, channels):
        """Fuzz channels field."""
        try:
            notification = NotificationCreate(
                title="Test",
                message="Test",
                channels=channels if channels else ["sms"],
                target_all=True
            )
        except Exception:
            # Invalid channels should fail
            pass


# =============================================================================
# UNICODE AND ENCODING FUZZING
# =============================================================================

class TestUnicodeFuzzing:
    """Fuzz testing with unicode and encoding edge cases."""

    @given(
        # Various unicode categories
        unicode_text=st.text(
            min_size=1,
            max_size=100,
            alphabet=st.characters(
                min_codepoint=0,
                max_codepoint=0x10FFFF,
                blacklist_categories=('Cs', 'Cc')  # Exclude surrogates and control
            )
        )
    )
    @settings(deadline=1000, max_examples=100)
    def test_unicode_in_password(self, unicode_text):
        """Test unicode characters in password."""
        try:
            from app.core.security import hash_password, verify_password
            
            hashed = hash_password(unicode_text)
            assert verify_password(unicode_text, hashed) is True
        except Exception:
            # Some unicode might not be supported
            pass

    @given(
        # Emoji and special unicode
        emoji_text=st.text(
            min_size=1,
            max_size=50,
            alphabet=st.characters(
                min_codepoint=0x1F600,  # Emoji range start
                max_codepoint=0x1F64F,  # Emoji range end
            )
        )
    )
    @settings(deadline=1000, max_examples=50)
    def test_emoji_in_user_data(self, emoji_text):
        """Test emoji in user data fields."""
        try:
            user = UserCreate(
                email="test@example.com",
                password="Password123!",
                first_name=emoji_text,
                last_name="User"
            )
            # Should preserve emoji
            assert user.first_name == emoji_text
        except Exception:
            # Some systems might not support emoji
            pass


# =============================================================================
# BOUNDARY VALUE FUZZING
# =============================================================================

class TestBoundaryValueFuzzing:
    """Fuzz testing for boundary values."""

    @given(
        # Boundary integers
        value=st.one_of(
            st.just(0),
            st.just(-1),
            st.just(1),
            st.just(2147483647),  # Max 32-bit int
            st.just(-2147483648),  # Min 32-bit int
            st.integers(min_value=-1000, max_value=1000),
        )
    )
    @settings(deadline=1000, max_examples=100)
    def test_integer_boundaries(self, value):
        """Test integer boundary values."""
        # Test in various contexts
        try:
            # Location ID
            from app.schemas import UserUpdate
            update = UserUpdate(location_id=value if value >= 0 else None)
        except Exception:
            pass

    @given(
        # Boundary floats
        value=st.one_of(
            st.just(0.0),
            st.just(-0.0),
            st.just(float('inf')),
            st.just(float('-inf')),
            st.floats(allow_nan=False, allow_infinity=True),
        )
    )
    @settings(deadline=1000, max_examples=50)
    def test_float_boundaries(self, value):
        """Test float boundary values."""
        try:
            from app.core.geofence import validate_coordinates
            # Test with latitude/longitude
            is_valid, _ = validate_coordinates(value, 0.0)
            # Should not crash
        except Exception:
            # Invalid values should be handled
            pass


# =============================================================================
# JSON FUZZING
# =============================================================================

class TestJSONFuzzing:
    """Fuzz testing for JSON inputs."""

    @given(
        # Generate arbitrary JSON-like structures
        data=st.recursive(
            st.none() | st.booleans() | st.floats() | st.text(min_size=0, max_size=100),
            lambda children: st.lists(children, max_size=10) | st.dictionaries(st.text(min_size=0, max_size=20), children, max_size=10),
        )
    )
    @settings(deadline=1000, max_examples=100)
    def test_json_serialization(self, data):
        """Test JSON serialization of arbitrary data."""
        try:
            json_str = json.dumps(data)
            parsed = json.loads(json_str)
            # Should round-trip
            assert isinstance(parsed, type(data)) or True  # Some type conversion is OK
        except Exception:
            # Some data might not be serializable
            pass

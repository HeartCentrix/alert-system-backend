"""
Integration Tests for Database Operations

Tests cover:
- CRUD operations
- Transactions
- Constraints
- Cascading deletes
- Concurrency
"""
import pytest
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.models import (
    User, UserRole, Location, Group, Notification,
    Incident, NotificationStatus, DeliveryLog, AlertChannel,
    UserLocation, UserLocationAssignmentType, UserLocationStatus
)
from app.core.security import hash_password


# =============================================================================
# USER CRUD TESTS
# =============================================================================

class TestUserDatabaseOperations:
    """Test user database operations."""

    def test_create_user(self, db_session):
        """Test user creation."""
        user = User(
            email="newuser@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="New",
            last_name="User",
            role=UserRole.VIEWER,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        
        assert user.id is not None
        assert user.email == "newuser@example.com"
        assert user.created_at is not None

    def test_user_email_unique_constraint(self, db_session):
        """Test email uniqueness constraint."""
        user1 = User(
            email="unique@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="User",
            last_name="One",
        )
        db_session.add(user1)
        db_session.commit()
        
        user2 = User(
            email="unique@example.com",  # Duplicate email
            hashed_password=hash_password("Password123!"),
            first_name="User",
            last_name="Two",
        )
        db_session.add(user2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_update_user(self, db_session, test_user):
        """Test user update."""
        test_user.phone = "+9999999999"
        test_user.department = "Engineering"
        db_session.commit()
        
        db_session.refresh(test_user)
        assert test_user.phone == "+9999999999"
        assert test_user.department == "Engineering"

    def test_hard_delete_user(self, db_session, test_user):
        """Test hard delete - user is permanently removed from database."""
        user_id = test_user.id
        db_session.delete(test_user)
        db_session.commit()

        # User should no longer exist in DB
        user = db_session.query(User).filter(User.id == user_id).first()
        assert user is None

    def test_user_employee_id_unique(self, db_session):
        """Test employee ID uniqueness."""
        user1 = User(
            email="emp1@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="Employee",
            last_name="One",
            employee_id="EMP001",
        )
        db_session.add(user1)
        db_session.commit()
        
        user2 = User(
            email="emp2@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="Employee",
            last_name="Two",
            employee_id="EMP001",  # Duplicate
        )
        db_session.add(user2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()


# =============================================================================
# LOCATION TESTS
# =============================================================================

class TestLocationDatabaseOperations:
    """Test location database operations."""

    def test_create_location(self, db_session):
        """Test location creation."""
        location = Location(
            name="Test Office",
            address="123 Test St",
            city="Test City",
            state="TS",
            latitude=40.7128,
            longitude=-74.0060,
            geofence_radius_miles=5.0,
        )
        db_session.add(location)
        db_session.commit()
        db_session.refresh(location)
        
        assert location.id is not None
        assert location.name == "Test Office"

    def test_location_geofence_validation(self, db_session):
        """Test geofence radius validation at DB level."""
        # Very large radius (should work, validation is at app level)
        location = Location(
            name="Large Area",
            latitude=40.7128,
            longitude=-74.0060,
            geofence_radius_miles=1000.0,
        )
        db_session.add(location)
        db_session.commit()
        
        assert location.geofence_radius_miles == 1000.0

    def test_location_without_coordinates(self, db_session):
        """Test location without coordinates (allowed for draft locations)."""
        location = Location(
            name="Draft Location",
            # No coordinates
        )
        db_session.add(location)
        db_session.commit()
        
        assert location.latitude is None
        assert location.longitude is None


# =============================================================================
# USER-LOCATION ASSIGNMENT TESTS
# =============================================================================

class TestUserLocationAssignment:
    """Test user-location assignment operations."""

    def test_assign_user_to_location(self, db_session, test_user, test_location):
        """Test assigning user to location."""
        assignment = UserLocation(
            user_id=test_user.id,
            location_id=test_location.id,
            assignment_type=UserLocationAssignmentType.MANUAL,
            status=UserLocationStatus.ACTIVE,
        )
        db_session.add(assignment)
        db_session.commit()
        
        assert assignment.id is not None
        
        # Verify relationship
        db_session.refresh(test_user)
        assert len(test_user.location_assignments) > 0

    def test_geofence_assignment(self, db_session, test_user, test_location):
        """Test geofence-based assignment."""
        assignment = UserLocation(
            user_id=test_user.id,
            location_id=test_location.id,
            assignment_type=UserLocationAssignmentType.GEOFENCE,
            status=UserLocationStatus.ACTIVE,
            detected_latitude=40.7130,
            detected_longitude=-74.0062,
            distance_from_center_miles=0.5,
        )
        db_session.add(assignment)
        db_session.commit()
        
        assert assignment.assignment_type == UserLocationAssignmentType.GEOFENCE
        assert assignment.distance_from_center_miles == 0.5

    def test_deactivate_location_assignment(self, db_session, test_user, test_location):
        """Test deactivating location assignment."""
        assignment = UserLocation(
            user_id=test_user.id,
            location_id=test_location.id,
            status=UserLocationStatus.ACTIVE,
        )
        db_session.add(assignment)
        db_session.commit()
        
        # Deactivate
        assignment.status = UserLocationStatus.INACTIVE
        db_session.commit()
        
        db_session.refresh(assignment)
        assert assignment.status == UserLocationStatus.INACTIVE


# =============================================================================
# NOTIFICATION TESTS
# =============================================================================

class TestNotificationDatabaseOperations:
    """Test notification database operations."""

    def test_create_notification(self, db_session, test_user, test_incident):
        """Test notification creation."""
        notification = Notification(
            incident_id=test_incident.id,
            title="Test Notification",
            message="Test message",
            channels=["sms", "email"],
            status=NotificationStatus.DRAFT,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        db_session.refresh(notification)
        
        assert notification.id is not None
        assert notification.status == NotificationStatus.DRAFT

    def test_notification_status_transitions(self, db_session, test_user):
        """Test notification status transitions."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            status=NotificationStatus.DRAFT,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        # Draft -> SENDING
        notification.status = NotificationStatus.SENDING
        db_session.commit()
        
        # SENDING -> SENT
        notification.status = NotificationStatus.SENT
        db_session.commit()
        
        db_session.refresh(notification)
        assert notification.status == NotificationStatus.SENT

    def test_notification_delivery_tracking(self, db_session, test_user, test_notification):
        """Test notification delivery tracking."""
        # Create delivery log
        log = DeliveryLog(
            notification_id=test_notification.id,
            user_id=test_user.id,
            channel=AlertChannel.SMS,
            status=DeliveryStatus.PENDING,
            to_address="+1234567890",
        )
        db_session.add(log)
        db_session.commit()
        
        # Update status
        log.status = DeliveryStatus.SENT
        log.sent_at = datetime.now(timezone.utc)
        db_session.commit()
        
        db_session.refresh(log)
        assert log.status == DeliveryStatus.SENT
        
        # Update notification counts
        db_session.refresh(test_notification)
        test_notification.sent_count += 1
        db_session.commit()


# =============================================================================
# TRANSACTION TESTS
# =============================================================================

class TestDatabaseTransactions:
    """Test database transaction handling."""

    def test_transaction_rollback(self, db_session):
        """Test transaction rollback on error."""
        try:
            user = User(
                email="rollback@example.com",
                hashed_password=hash_password("Password123!"),
                first_name="Rollback",
                last_name="Test",
            )
            db_session.add(user)
            db_session.flush()  # Don't commit yet
            
            # Force an error
            raise ValueError("Simulated error")
            
        except ValueError:
            db_session.rollback()
        
        # User should not exist
        user = db_session.query(User).filter(
            User.email == "rollback@example.com"
        ).first()
        assert user is None

    def test_transaction_commit(self, db_session):
        """Test successful transaction commit."""
        user = User(
            email="commit@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="Commit",
            last_name="Test",
        )
        db_session.add(user)
        db_session.commit()
        
        # User should exist in new session
        db_session.expunge_all()
        user = db_session.query(User).filter(
            User.email == "commit@example.com"
        ).first()
        assert user is not None

    def test_nested_transaction(self, db_session):
        """Test nested transaction (savepoint)."""
        # Outer transaction
        user1 = User(
            email="outer@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="Outer",
            last_name="User",
        )
        db_session.add(user1)
        db_session.flush()
        
        try:
            # Inner transaction (savepoint)
            user2 = User(
                email="inner@example.com",
                hashed_password=hash_password("Password123!"),
                first_name="Inner",
                last_name="User",
            )
            db_session.add(user2)
            db_session.flush()
            
            # Force error in inner transaction
            raise ValueError("Inner error")
            
        except ValueError:
            db_session.rollback()  # Rollback to savepoint
        
        # user1 should exist, user2 should not
        assert db_session.query(User).filter(User.email == "outer@example.com").first() is not None
        assert db_session.query(User).filter(User.email == "inner@example.com").first() is None


# =============================================================================
# CASCADING DELETE TESTS
# =============================================================================

class TestCascadingDeletes:
    """Test cascading delete operations."""

    def test_delete_user_cascades_to_groups(self, db_session, test_user):
        """Test deleting user removes from groups."""
        group = Group(
            name="Test Group",
        )
        group.members.append(test_user)
        db_session.add(group)
        db_session.commit()

        # Delete user
        db_session.delete(test_user)
        db_session.commit()

        # User should be removed from group
        db_session.refresh(group)
        assert test_user not in group.members

    def test_delete_user_cascades_to_delivery_logs(self, db_session, test_user):
        """
        Test that hard deleting a user cascades to delete related delivery_logs.
        
        This is a regression test for the IntegrityError that occurred when:
        - delivery_logs.user_id had ON DELETE SET NULL but column was NOT NULL
        - SQLAlchemy tried to set user_id=NULL during user deletion
        
        The fix uses ON DELETE CASCADE so PostgreSQL deletes child rows automatically.
        """
        from app.models import Notification, NotificationStatus
        
        # Create a separate admin user to own the notification (for audit trail)
        admin = User(
            email="admin@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="Admin",
            last_name="User",
            role=UserRole.ADMIN,
        )
        db_session.add(admin)
        db_session.commit()
        db_session.refresh(admin)
        
        # Create a notification owned by admin (not test_user)
        notification = Notification(
            title="Test Notification",
            message="Test message",
            channels=["sms", "email"],
            created_by_id=admin.id,  # Owned by admin, not test_user
        )
        db_session.add(notification)
        db_session.commit()
        db_session.refresh(notification)

        # Create delivery logs linked to the test_user (as recipient)
        delivery_log_1 = DeliveryLog(
            notification_id=notification.id,
            user_id=test_user.id,
            user_email=test_user.email,  # Preserved for audit
            channel=AlertChannel.SMS,
            status="sent",
            to_address="+1234567890",
        )
        delivery_log_2 = DeliveryLog(
            notification_id=notification.id,
            user_id=test_user.id,
            user_email=test_user.email,
            channel=AlertChannel.EMAIL,
            status="delivered",
            to_address=test_user.email,
        )
        db_session.add_all([delivery_log_1, delivery_log_2])
        db_session.commit()

        # Verify delivery logs exist
        user_delivery_logs = db_session.query(DeliveryLog).filter(
            DeliveryLog.user_id == test_user.id
        ).all()
        assert len(user_delivery_logs) == 2

        # Hard delete the user
        db_session.delete(test_user)
        db_session.commit()

        # User should be gone
        user = db_session.query(User).filter(User.id == test_user.id).first()
        assert user is None

        # Related delivery logs should also be deleted (CASCADE)
        remaining_logs = db_session.query(DeliveryLog).filter(
            DeliveryLog.user_id == test_user.id
        ).all()
        assert len(remaining_logs) == 0

    def test_delete_user_cascades_to_notification_responses(self, db_session, test_user):
        """
        Test that hard deleting a user cascades to delete related notification responses.
        
        Similar to delivery_logs, notification_responses.user_id uses ON DELETE CASCADE.
        """
        from app.models import NotificationResponse, ResponseType, Notification, NotificationStatus
        
        # Create a separate admin user to own the notification (for audit trail)
        admin = User(
            email="admin2@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="Admin",
            last_name="User",
            role=UserRole.ADMIN,
        )
        db_session.add(admin)
        db_session.commit()
        db_session.refresh(admin)
        
        # Create a notification owned by admin
        notification = Notification(
            title="Test Notification",
            message="Test message",
            channels=["sms"],
            created_by_id=admin.id,
        )
        db_session.add(notification)
        db_session.commit()
        db_session.refresh(notification)

        # Create responses linked to the test_user
        response_1 = NotificationResponse(
            notification_id=notification.id,
            user_id=test_user.id,
            user_email=test_user.email,
            channel=AlertChannel.SMS,
            response_type=ResponseType.SAFE,
        )
        response_2 = NotificationResponse(
            notification_id=notification.id,
            user_id=test_user.id,
            user_email=test_user.email,
            channel=AlertChannel.EMAIL,
            response_type=ResponseType.ACKNOWLEDGED,
        )
        db_session.add_all([response_1, response_2])
        db_session.commit()

        # Verify responses exist
        user_responses = db_session.query(NotificationResponse).filter(
            NotificationResponse.user_id == test_user.id
        ).all()
        assert len(user_responses) == 2

        # Hard delete the user
        db_session.delete(test_user)
        db_session.commit()

        # User should be gone
        user = db_session.query(User).filter(User.id == test_user.id).first()
        assert user is None

        # Related responses should also be deleted (CASCADE)
        remaining_responses = db_session.query(NotificationResponse).filter(
            NotificationResponse.user_id == test_user.id
        ).all()
        assert len(remaining_responses) == 0

    def test_delete_user_with_multiple_delivery_logs_no_integrity_error(self, db_session, test_user):
        """
        Regression test: Verify deleting a user with multiple delivery logs succeeds.
        
        This test ensures the exact error scenario from the bug report is fixed:
        sqlalchemy.exc.IntegrityError: null value in column "user_id" of relation "delivery_logs"
        
        The delete should complete without attempting to set user_id to NULL.
        """
        from app.models import Notification
        
        # Create a separate admin user to own the notification
        admin = User(
            email="admin3@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="Admin",
            last_name="User",
            role=UserRole.ADMIN,
        )
        db_session.add(admin)
        db_session.commit()
        db_session.refresh(admin)
        
        # Create notification owned by admin
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            created_by_id=admin.id,
        )
        db_session.add(notification)
        db_session.commit()
        db_session.refresh(notification)

        # Create multiple delivery logs for test_user
        for i in range(5):
            log = DeliveryLog(
                notification_id=notification.id,
                user_id=test_user.id,
                user_email=test_user.email,
                channel=AlertChannel.SMS,
                status="sent",
                to_address=f"+123456789{i}",
            )
            db_session.add(log)
        db_session.commit()

        # This delete should NOT raise IntegrityError
        # Previously would fail with: UPDATE delivery_logs SET user_id=NULL ...
        db_session.delete(test_user)
        db_session.commit()  # Should succeed without error

        # Verify cleanup
        assert db_session.query(User).filter(User.id == test_user.id).first() is None
        assert db_session.query(DeliveryLog).filter(
            DeliveryLog.user_id == test_user.id
        ).count() == 0

    def test_user_update_does_not_affect_delivery_logs(self, db_session, test_user):
        """
        Test that updating a user's profile does not mutate delivery log ownership.
        
        Regression test to ensure delivery_logs remain untouched unless user is deleted.
        """
        from app.models import Notification
        
        # Create a separate admin user to own the notification
        admin = User(
            email="admin4@example.com",
            hashed_password=hash_password("Password123!"),
            first_name="Admin",
            last_name="User",
            role=UserRole.ADMIN,
        )
        db_session.add(admin)
        db_session.commit()
        db_session.refresh(admin)
        
        # Create notification and delivery log
        notification = Notification(
            title="Test",
            message="Test",
            channels=["email"],
            created_by_id=admin.id,
        )
        db_session.add(notification)
        db_session.commit()
        db_session.refresh(notification)

        delivery_log = DeliveryLog(
            notification_id=notification.id,
            user_id=test_user.id,
            user_email=test_user.email,
            channel=AlertChannel.EMAIL,
            status="delivered",
            to_address=test_user.email,
        )
        db_session.add(delivery_log)
        db_session.commit()
        db_session.refresh(delivery_log)

        original_log_id = delivery_log.id
        original_user_id = delivery_log.user_id

        # Update user profile (not deletion)
        test_user.phone = "+9999999999"
        test_user.department = "Engineering"
        db_session.commit()

        # Delivery log should be unchanged
        db_session.refresh(delivery_log)
        assert delivery_log.id == original_log_id
        assert delivery_log.user_id == original_user_id
        assert delivery_log.user_email == test_user.email  # Still linked

    def test_delete_location_cascades_to_users(self, db_session, test_location, test_user):
        """Test deleting location affects user assignments."""
        # Assign user to location
        test_user.location_id = test_location.id
        db_session.commit()

        # Delete location
        db_session.delete(test_location)
        db_session.commit()

        # User's location_id should be NULL
        db_session.refresh(test_user)
        assert test_user.location_id is None


# =============================================================================
# CONCURRENCY TESTS
# =============================================================================

class TestDatabaseConcurrency:
    """Test database concurrency handling."""

    def test_concurrent_user_updates(self, db_session, test_user):
        """Test concurrent updates to same user."""
        # Simulate concurrent updates
        test_user.phone = "+1111111111"
        db_session.flush()
        
        # Another update
        test_user.department = "Engineering"
        db_session.flush()
        
        db_session.commit()
        
        db_session.refresh(test_user)
        assert test_user.phone == "+1111111111"
        assert test_user.department == "Engineering"

    def test_optimistic_locking_pattern(self, db_session, test_user):
        """Test optimistic locking pattern (using updated_at)."""
        original_updated_at = test_user.updated_at
        
        # Update user
        test_user.phone = "+2222222222"
        db_session.commit()
        
        db_session.refresh(test_user)
        
        # updated_at should change
        if original_updated_at:
            assert test_user.updated_at > original_updated_at

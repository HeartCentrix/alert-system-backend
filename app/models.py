from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, Enum, Float, JSON, Table
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import enum


# ─── ENUMS ────────────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MANAGER = "manager"
    VIEWER = "viewer"


class GroupType(str, enum.Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"


class NotificationStatus(str, enum.Enum):
    DRAFT = "draft"
    SENDING = "sending"
    SENT = "sent"
    PARTIALLY_SENT = "partially_sent"
    FAILED = "failed"
    SCHEDULED = "scheduled"
    CANCELLED = "cancelled"


class DeliveryStatus(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    BOUNCED = "bounced"


class ResponseType(str, enum.Enum):
    SAFE = "safe"
    NEED_HELP = "need_help"
    ACKNOWLEDGED = "acknowledged"
    CUSTOM = "custom"


class AlertChannel(str, enum.Enum):
    SMS = "sms"
    EMAIL = "email"
    VOICE = "voice"
    WHATSAPP = "whatsapp"
    SLACK = "slack"
    TEAMS = "teams"
    WEB = "web"


class IncidentSeverity(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, enum.Enum):
    ACTIVE = "active"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    CANCELLED = "cancelled"


# ─── ASSOCIATION TABLES ───────────────────────────────────────────────────────

group_members = Table(
    "group_members",
    Base.metadata,
    Column("group_id", Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)

notification_groups = Table(
    "notification_groups",
    Base.metadata,
    Column("notification_id", Integer, ForeignKey("notifications.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)

notification_users = Table(
    "notification_users",
    Base.metadata,
    Column("notification_id", Integer, ForeignKey("notifications.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)


# ─── MODELS ───────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    phone = Column(String(20))
    whatsapp_number = Column(String(20))
    department = Column(String(100))
    title = Column(String(100))
    employee_id = Column(String(50), unique=True)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32))
    avatar_url = Column(String(500))
    preferred_channels = Column(JSON, default=["sms", "email"])
    latitude = Column(Float, nullable=True)   # Last known latitude
    longitude = Column(Float, nullable=True)  # Last known longitude
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)
    last_login = Column(DateTime(timezone=True))
    password_reset_token = Column(String(100))
    password_reset_expires = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True))

    location = relationship("Location", back_populates="users")
    groups = relationship("Group", secondary=group_members, back_populates="members")
    delivery_logs = relationship("DeliveryLog", back_populates="user")
    responses = relationship("NotificationResponse", back_populates="user")

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"


class Location(Base):
    __tablename__ = "locations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    address = Column(String(500))
    city = Column(String(100))
    state = Column(String(50))
    zip_code = Column(String(20))
    country = Column(String(100), default="USA")
    latitude = Column(Float)
    longitude = Column(Float)
    geofence_radius_miles = Column(Float, default=1.0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    users = relationship("User", back_populates="location")
    groups = relationship("Group", back_populates="location")


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    type = Column(Enum(GroupType), default=GroupType.STATIC, nullable=False)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)
    dynamic_filter = Column(JSON)  # e.g. {"department": "IT", "location_id": 1}
    is_active = Column(Boolean, default=True)
    created_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    location = relationship("Location", back_populates="groups")
    created_by = relationship("User", foreign_keys=[created_by_id])
    members = relationship("User", secondary=group_members, back_populates="groups")
    notifications = relationship("Notification", secondary=notification_groups, back_populates="target_groups")

    @property
    def member_count(self):
        return len(self.members)


class NotificationTemplate(Base):
    __tablename__ = "notification_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    category = Column(String(100))  # weather, security, IT, facility, health, custom
    subject = Column(String(500))
    body = Column(Text, nullable=False)
    channels = Column(JSON, default=["sms", "email"])
    variables = Column(JSON)  # list of {name, description} placeholders
    is_active = Column(Boolean, default=True)
    created_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    created_by = relationship("User", foreign_keys=[created_by_id])


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False)
    type = Column(String(100))  # weather, security, IT, facility, health, custom
    severity = Column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.ACTIVE)
    description = Column(Text)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    resolved_at = Column(DateTime(timezone=True))
    resolved_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    location = relationship("Location")
    created_by = relationship("User", foreign_keys=[created_by_id])
    resolved_by = relationship("User", foreign_keys=[resolved_by_id])
    notifications = relationship("Notification", back_populates="incident")


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    template_id = Column(Integer, ForeignKey("notification_templates.id"), nullable=True)
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=False)
    subject = Column(String(500))  # for email
    channels = Column(JSON, nullable=False)  # ["sms","email","voice","whatsapp","slack","teams"]
    status = Column(Enum(NotificationStatus), default=NotificationStatus.DRAFT)
    target_all = Column(Boolean, default=False)
    scheduled_at = Column(DateTime(timezone=True))
    sent_at = Column(DateTime(timezone=True))
    total_recipients = Column(Integer, default=0)
    sent_count = Column(Integer, default=0)
    delivered_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    response_required = Column(Boolean, default=False)
    response_deadline_minutes = Column(Integer)
    slack_webhook_url = Column(String(500))
    teams_webhook_url = Column(String(500))
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    incident = relationship("Incident", back_populates="notifications")
    template = relationship("NotificationTemplate")
    created_by = relationship("User", foreign_keys=[created_by_id])
    target_groups = relationship("Group", secondary=notification_groups, back_populates="notifications")
    target_users = relationship("User", secondary=notification_users)
    delivery_logs = relationship("DeliveryLog", back_populates="notification")
    responses = relationship("NotificationResponse", back_populates="notification")


class DeliveryLog(Base):
    __tablename__ = "delivery_logs"

    id = Column(Integer, primary_key=True, index=True)
    notification_id = Column(Integer, ForeignKey("notifications.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    channel = Column(Enum(AlertChannel), nullable=False)
    status = Column(Enum(DeliveryStatus), default=DeliveryStatus.PENDING)
    external_id = Column(String(200))  # Twilio SID, SES MessageId, etc.
    to_address = Column(String(255))  # phone or email
    error_message = Column(Text)
    sent_at = Column(DateTime(timezone=True))
    delivered_at = Column(DateTime(timezone=True))
    failed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    notification = relationship("Notification", back_populates="delivery_logs")
    user = relationship("User", back_populates="delivery_logs")


class NotificationResponse(Base):
    __tablename__ = "notification_responses"

    id = Column(Integer, primary_key=True, index=True)
    notification_id = Column(Integer, ForeignKey("notifications.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    channel = Column(Enum(AlertChannel))
    response_type = Column(Enum(ResponseType), nullable=False)
    message = Column(Text)
    latitude = Column(Float)
    longitude = Column(Float)
    from_number = Column(String(20))
    responded_at = Column(DateTime(timezone=True), server_default=func.now())

    notification = relationship("Notification", back_populates="responses")
    user = relationship("User", back_populates="responses")


class IncomingMessage(Base):
    __tablename__ = "incoming_messages"

    id = Column(Integer, primary_key=True, index=True)
    from_number = Column(String(20), nullable=False)
    to_number = Column(String(20))
    body = Column(Text)
    channel = Column(Enum(AlertChannel), default=AlertChannel.SMS)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    notification_id = Column(Integer, ForeignKey("notifications.id"), nullable=True)
    is_processed = Column(Boolean, default=False)
    received_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")
    notification = relationship("Notification")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(200), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(Integer)
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(500), unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")


class LoginAttempt(Base):
    """Track failed login attempts for brute force protection."""
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)  # Track by email
    ip_address = Column(String(45))  # Track by IP
    attempted_at = Column(DateTime(timezone=True), server_default=func.now())
    success = Column(Boolean, default=False)
# ─── LOCATION AUDIENCE MANAGEMENT ─────────────────────────────────────────────

class UserLocationAssignmentType(str, enum.Enum):
    """How the user was assigned to this location."""
    MANUAL = "manual"  # Admin manually assigned
    GEOFENCE = "geofence"  # Auto-assigned via geofence detection


class UserLocationStatus(str, enum.Enum):
    """Current status of the location membership."""
    ACTIVE = "active"
    INACTIVE = "inactive"  # User exited geofence or was removed


class UserLocation(Base):
    """
    Many-to-many relationship between users and locations.
    
    Tracks both manual assignments by admins and automatic geofence-based assignments.
    A user can belong to multiple locations simultaneously.
    """
    __tablename__ = "user_locations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey("locations.id", ondelete="CASCADE"), nullable=False, index=True)
    assignment_type = Column(Enum(UserLocationAssignmentType), nullable=False, default=UserLocationAssignmentType.MANUAL)
    status = Column(Enum(UserLocationStatus), nullable=False, default=UserLocationStatus.ACTIVE)
    
    # For geofence assignments: track the coordinates that triggered the assignment
    detected_latitude = Column(Float, nullable=True)
    detected_longitude = Column(Float, nullable=True)
    distance_from_center_miles = Column(Float, nullable=True)  # Distance when assigned
    
    # Metadata
    assigned_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Admin who manually assigned (if manual)
    notes = Column(Text, nullable=True)
    
    # Timestamps
    assigned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration for temporary assignments
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Unique constraint: one active assignment per user-location pair
    __table_args__ = (
        # Prevent duplicate active assignments
        # (handled at application level for flexibility with status changes)
    )

    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="location_assignments")
    location = relationship("Location", back_populates="user_assignments")
    assigned_by = relationship("User", foreign_keys=[assigned_by_id])


class UserLocationHistory(Base):
    """
    Audit trail for all location membership changes.
    
    Records every assignment, removal, and status change for compliance and debugging.
    """
    __tablename__ = "user_location_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey("locations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_location_id = Column(Integer, ForeignKey("user_locations.id", ondelete="CASCADE"), nullable=True)  # Reference to current record
    
    # Action taken
    action = Column(String(50), nullable=False)  # assigned, removed, entered_geofence, exited_geofence, status_changed
    assignment_type = Column(Enum(UserLocationAssignmentType), nullable=True)
    previous_status = Column(Enum(UserLocationStatus), nullable=True)
    new_status = Column(Enum(UserLocationStatus), nullable=True)
    
    # Context
    triggered_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Admin who triggered (if manual)
    reason = Column(Text, nullable=True)
    
    # Location data at time of action
    detected_latitude = Column(Float, nullable=True)
    detected_longitude = Column(Float, nullable=True)
    distance_from_center_miles = Column(Float, nullable=True)
    
    # Metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    extra_data = Column(JSON, nullable=True)  # Additional context (renamed from 'metadata' to avoid conflict)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    location = relationship("Location")
    triggered_by = relationship("User", foreign_keys=[triggered_by_user_id])


# Add back-references to User and Location models
User.location_assignments = relationship("UserLocation", foreign_keys=[UserLocation.user_id], back_populates="user")
Location.user_assignments = relationship("UserLocation", foreign_keys=[UserLocation.location_id], back_populates="location")

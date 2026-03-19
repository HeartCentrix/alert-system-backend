from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, Enum, Float, JSON, Table, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import enum

# ─── FOREIGN KEY REFERENCE CONSTANTS ─────────────────────────────────────────
USERS_ID_FK = "users.id"
NOTIFICATIONS_ID_FK = "notifications.id"
LOCATIONS_ID_FK = "locations.id"



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
    Column("user_id", Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), primary_key=True),
)

notification_groups = Table(
    "notification_groups",
    Base.metadata,
    Column("notification_id", Integer, ForeignKey(NOTIFICATIONS_ID_FK, ondelete="CASCADE"), primary_key=True),
    Column("group_id", Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)

notification_users = Table(
    "notification_users",
    Base.metadata,
    Column("notification_id", Integer, ForeignKey(NOTIFICATIONS_ID_FK, ondelete="CASCADE"), primary_key=True),
    Column("user_id", Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), primary_key=True),
)


# ─── MODELS ───────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)  # Nullable for SSO/LDAP users
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    phone = Column(String(20), unique=True, index=True, nullable=True)  # Unique phone number per user
    department = Column(String(100))
    title = Column(String(100))
    employee_id = Column(String(50), unique=True)
    role = Column(Enum(UserRole, values_callable=lambda x: [e.value for e in x]), default=UserRole.VIEWER, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)  # Account status - admin controlled
    is_active = Column(Boolean, default=False)  # DEPRECATED: use is_online instead
    is_online = Column(Boolean, default=False)  # Real-time online presence (heartbeat)
    is_verified = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255))  # Increased from 32 to store Fernet-encrypted secrets
    last_used_totp_code = Column(String(6), nullable=True, default=None)
    last_used_totp_at = Column(DateTime(timezone=True), nullable=True, default=None)
    avatar_url = Column(String(500))
    preferred_channels = Column(JSON, default=["sms", "email"])
    latitude = Column(Float, nullable=True)   # Last known latitude
    longitude = Column(Float, nullable=True)  # Last known longitude
    location_id = Column(Integer, ForeignKey(LOCATIONS_ID_FK), nullable=True)
    last_login = Column(DateTime(timezone=True))
    last_seen_at = Column(DateTime(timezone=True), nullable=True)  # Last heartbeat timestamp
    password_reset_token = Column(String(100))
    password_reset_expires = Column(DateTime(timezone=True))
    token_valid_after = Column(DateTime(timezone=True), nullable=True)
    force_password_change = Column(Boolean, default=False, nullable=False)
    auth_provider = Column(String(20), default="local", nullable=False, server_default="local")  # "local", "entra", "ldap"
    external_id = Column(String(255), nullable=True, unique=True, index=True)  # Entra OID or LDAP DN
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    location = relationship("Location", back_populates="users")
    groups = relationship("Group", secondary=group_members, back_populates="members")
    delivery_logs = relationship("DeliveryLog", back_populates="user", passive_deletes=True)
    responses = relationship("NotificationResponse", back_populates="user", passive_deletes=True)

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
    type = Column(Enum(GroupType, values_callable=lambda x: [e.value for e in x]), default=GroupType.STATIC, nullable=False)
    location_id = Column(Integer, ForeignKey(LOCATIONS_ID_FK), nullable=True)
    dynamic_filter = Column(JSON)  # e.g. {"department": "IT", "location_id": 1}
    is_active = Column(Boolean, default=True)
    created_by_id = Column(Integer, ForeignKey(USERS_ID_FK))
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
    created_by_id = Column(Integer, ForeignKey(USERS_ID_FK))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    created_by = relationship("User", foreign_keys=[created_by_id])


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False)
    type = Column(String(100))  # weather, security, IT, facility, health, custom
    severity = Column(Enum(IncidentSeverity, values_callable=lambda x: [e.value for e in x]), default=IncidentSeverity.MEDIUM)
    status = Column(Enum(IncidentStatus, values_callable=lambda x: [e.value for e in x]), default=IncidentStatus.ACTIVE)
    description = Column(Text)
    location_id = Column(Integer, ForeignKey(LOCATIONS_ID_FK), nullable=True)
    created_by_id = Column(Integer, ForeignKey(USERS_ID_FK), nullable=False)
    resolved_at = Column(DateTime(timezone=True))
    resolved_by_id = Column(Integer, ForeignKey(USERS_ID_FK))
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
    channels = Column(JSON, nullable=False)  # ["sms","email","voice","slack","teams"]
    status = Column(Enum(NotificationStatus, values_callable=lambda x: [e.value for e in x]), default=NotificationStatus.DRAFT)
    target_all = Column(Boolean, default=False)
    scheduled_at = Column(DateTime(timezone=True))
    scheduled_timezone = Column(String(100))  # Original timezone (e.g., "America/New_York")
    sent_at = Column(DateTime(timezone=True))
    total_recipients = Column(Integer, default=0)
    sent_count = Column(Integer, default=0)
    delivered_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    response_required = Column(Boolean, default=False)
    response_deadline_minutes = Column(Integer)
    deadline_escalated = Column(Boolean, default=False)  # Track if deadline escalation was sent
    slack_webhook_url = Column(String(500))
    teams_webhook_url = Column(String(500))
    created_by_id = Column(Integer, ForeignKey(USERS_ID_FK), nullable=False)
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
    __table_args__ = (
        UniqueConstraint('notification_id', 'user_id', 'channel', name='uq_delivery_log_notification_user_channel'),
    )

    id = Column(Integer, primary_key=True, index=True)
    notification_id = Column(Integer, ForeignKey(NOTIFICATIONS_ID_FK, ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), nullable=False)
    user_email = Column(String(255), nullable=True)  # Preserved after user deletion
    channel = Column(Enum(AlertChannel, values_callable=lambda x: [e.value for e in x]), nullable=False)
    status = Column(Enum(DeliveryStatus, values_callable=lambda x: [e.value for e in x]), default=DeliveryStatus.PENDING)
    external_id = Column(String(200))  # Twilio SID, SES MessageId, etc.
    to_address = Column(String(255))  # phone or email
    error_message = Column(Text)
    sent_at = Column(DateTime(timezone=True))
    delivered_at = Column(DateTime(timezone=True))
    failed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    notification = relationship("Notification", back_populates="delivery_logs")
    user = relationship("User", back_populates="delivery_logs", foreign_keys=[user_id])


class NotificationResponse(Base):
    __tablename__ = "notification_responses"

    id = Column(Integer, primary_key=True, index=True)
    notification_id = Column(Integer, ForeignKey(NOTIFICATIONS_ID_FK, ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), nullable=False)
    user_email = Column(String(255), nullable=True)  # Preserved after user deletion
    channel = Column(Enum(AlertChannel, values_callable=lambda x: [e.value for e in x]))
    response_type = Column(Enum(ResponseType, values_callable=lambda x: [e.value for e in x]), nullable=False)
    message = Column(Text)
    latitude = Column(Float)
    longitude = Column(Float)
    from_number = Column(String(20))
    responded_at = Column(DateTime(timezone=True), server_default=func.now())

    notification = relationship("Notification", back_populates="responses")
    user = relationship("User", back_populates="responses", foreign_keys=[user_id])


class IncomingMessage(Base):
    __tablename__ = "incoming_messages"

    id = Column(Integer, primary_key=True, index=True)
    from_number = Column(String(20), nullable=False)
    to_number = Column(String(20))
    body = Column(Text)
    channel = Column(Enum(AlertChannel, values_callable=lambda x: [e.value for e in x]), default=AlertChannel.SMS)
    user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), nullable=False)
    user_email = Column(String(255), nullable=True)  # Preserved after user deletion
    notification_id = Column(Integer, ForeignKey(NOTIFICATIONS_ID_FK), nullable=True)
    is_processed = Column(Boolean, default=False)
    received_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")
    notification = relationship("Notification")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="SET NULL"), nullable=True)
    user_email = Column(String(255), nullable=True)  # Preserved after user deletion
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
    user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), nullable=False)
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
    user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey(LOCATIONS_ID_FK, ondelete="CASCADE"), nullable=False, index=True)
    assignment_type = Column(Enum(UserLocationAssignmentType, values_callable=lambda x: [e.value for e in x]), nullable=False, default=UserLocationAssignmentType.MANUAL)
    status = Column(Enum(UserLocationStatus, values_callable=lambda x: [e.value for e in x]), nullable=False, default=UserLocationStatus.ACTIVE)
    
    # For geofence assignments: track the coordinates that triggered the assignment
    detected_latitude = Column(Float, nullable=True)
    detected_longitude = Column(Float, nullable=True)
    distance_from_center_miles = Column(Float, nullable=True)  # Distance when assigned
    
    # Metadata
    assigned_by_id = Column(Integer, ForeignKey(USERS_ID_FK), nullable=True)  # Admin who manually assigned (if manual)
    notes = Column(Text, nullable=True)
    
    # Timestamps
    assigned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration for temporary assignments
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Unique constraint: one active assignment per user-location pair
    __table_args__ = (
        # Prevent duplicate active assignments at database level
        # This ensures atomicity and prevents race conditions
        UniqueConstraint('user_id', 'location_id', 'status', name='uq_user_location_active'),
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
    user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey(LOCATIONS_ID_FK, ondelete="CASCADE"), nullable=False, index=True)
    user_location_id = Column(Integer, ForeignKey("user_locations.id", ondelete="CASCADE"), nullable=True)  # Reference to current record
    
    # Action taken
    action = Column(String(50), nullable=False)  # assigned, removed, entered_geofence, exited_geofence, status_changed
    assignment_type = Column(Enum(UserLocationAssignmentType, values_callable=lambda x: [e.value for e in x]), nullable=True)
    previous_status = Column(Enum(UserLocationStatus, values_callable=lambda x: [e.value for e in x]), nullable=True)
    new_status = Column(Enum(UserLocationStatus, values_callable=lambda x: [e.value for e in x]), nullable=True)
    
    # Context
    triggered_by_user_id = Column(Integer, ForeignKey(USERS_ID_FK), nullable=True)  # Admin who triggered (if manual)
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


# ─── MFA RECOVERY CODES ───────────────────────────────────────────────────────

class MFARecoveryCode(Base):
    """
    Single-use recovery codes for MFA backup access.
    
    Security properties:
    - Only hashed codes are stored (never plaintext)
    - Single-use: marked as used after first successful authentication
    - High entropy: 12-character alphanumeric codes
    - Batched: regeneration creates new batch, invalidates old unused codes
    - Audit trail: tracks when used, from which IP
    
    OWASP compliance:
    - Securely generated random codes
    - Long enough to resist brute force (12+ chars)
    - Single-use only
    - Protected by rate limiting
    - User notified when used
    """
    __tablename__ = "mfa_recovery_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="CASCADE"), nullable=False, index=True)
    
    # Hashed code (bcrypt or SHA256 with salt)
    # Never store plaintext recovery codes
    code_hash = Column(String(255), nullable=False, index=True)
    
    # Batch ID - all codes generated together share same batch
    # Regenerating creates new batch and invalidates old unused codes
    batch_id = Column(String(64), nullable=False, index=True)
    
    # Status tracking
    is_used = Column(Boolean, default=False, nullable=False, index=True)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    used_ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    used_user_agent = Column(String(500), nullable=True)
    
    # Optional: track which admin/generated context
    generated_by_user_id = Column(Integer, ForeignKey(USERS_ID_FK, ondelete="SET NULL"), nullable=True)
    generation_reason = Column(String(100), nullable=True)  # 'initial_setup', 'regenerated', 'admin_reset'
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="mfa_recovery_codes")
    generated_by = relationship("User", foreign_keys=[generated_by_user_id])


# Add back-reference to User model
User.mfa_recovery_codes = relationship("MFARecoveryCode", foreign_keys=[MFARecoveryCode.user_id], back_populates="user", cascade="all, delete-orphan")

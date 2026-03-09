from pydantic import BaseModel, EmailStr, Field, validator, field_validator
from typing import Optional, List, Any, Dict
from datetime import datetime
from app.models import (
    UserRole, GroupType, NotificationStatus, DeliveryStatus,
    ResponseType, AlertChannel, IncidentSeverity, IncidentStatus,
    UserLocationAssignmentType, UserLocationStatus
)


# ─── AUTH ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: "UserResponse"


class RefreshRequest(BaseModel):
    refresh_token: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


# ─── USER ─────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    first_name: str
    last_name: str
    phone: Optional[str] = None
    whatsapp_number: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    employee_id: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    location_id: Optional[int] = None
    preferred_channels: List[str] = ["sms", "email"]


class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    whatsapp_number: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    employee_id: Optional[str] = None
    role: Optional[UserRole] = None
    location_id: Optional[int] = None
    is_active: Optional[bool] = None
    preferred_channels: Optional[List[str]] = None


class UserResponse(BaseModel):
    id: int
    email: str
    first_name: str
    last_name: str
    full_name: str
    phone: Optional[str]
    whatsapp_number: Optional[str]
    department: Optional[str]
    title: Optional[str]
    employee_id: Optional[str]
    role: UserRole
    is_active: bool
    location_id: Optional[int]
    preferred_channels: Optional[List[str]]
    created_at: datetime

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[UserResponse]


class CSVImportResponse(BaseModel):
    created: int
    updated: int
    failed: int
    errors: List[str]
    # Passwords for newly created users (only for new accounts, not updates)
    created_users: List[dict] = []  # [{email, password}, ...]


# ─── LOCATION ─────────────────────────────────────────────────────────────────

class LocationCreate(BaseModel):
    name: str
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: str = "USA"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    geofence_radius_miles: float = 1.0


class LocationUpdate(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    geofence_radius_miles: Optional[float] = None
    is_active: Optional[bool] = None


class LocationResponse(BaseModel):
    id: int
    name: str
    address: Optional[str]
    city: Optional[str]
    state: Optional[str]
    zip_code: Optional[str]
    country: str
    latitude: Optional[float]
    longitude: Optional[float]
    geofence_radius_miles: float
    is_active: bool
    user_count: Optional[int] = 0
    created_at: datetime

    class Config:
        from_attributes = True


# ─── GROUP ────────────────────────────────────────────────────────────────────

class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    type: GroupType = GroupType.STATIC
    location_id: Optional[int] = None
    dynamic_filter: Optional[dict] = None
    member_ids: Optional[List[int]] = []


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    location_id: Optional[int] = None
    dynamic_filter: Optional[dict] = None
    is_active: Optional[bool] = None
    member_ids: Optional[List[int]] = None  # Replace entire member list if provided


class GroupMemberAdd(BaseModel):
    user_ids: List[int]


class GroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    type: GroupType
    location_id: Optional[int]
    dynamic_filter: Optional[dict]
    is_active: bool
    member_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class GroupDetailResponse(GroupResponse):
    members: List[UserResponse]

    class Config:
        from_attributes = True


# ─── TEMPLATE ─────────────────────────────────────────────────────────────────

class TemplateCreate(BaseModel):
    name: str
    category: Optional[str] = None
    subject: Optional[str] = None
    body: str
    channels: List[str] = ["sms", "email"]
    variables: Optional[List[dict]] = None


class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    channels: Optional[List[str]] = None
    is_active: Optional[bool] = None


class TemplateResponse(BaseModel):
    id: int
    name: str
    category: Optional[str]
    subject: Optional[str]
    body: str
    channels: List[str]
    variables: Optional[List[dict]]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ─── INCIDENT ─────────────────────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str
    type: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    description: Optional[str] = None
    location_id: Optional[int] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    description: Optional[str] = None


class IncidentResponse(BaseModel):
    id: int
    title: str
    type: Optional[str]
    severity: IncidentSeverity
    status: IncidentStatus
    description: Optional[str]
    location_id: Optional[int]
    created_by_id: int
    resolved_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# ─── NOTIFICATION ─────────────────────────────────────────────────────────────

class NotificationCreate(BaseModel):
    incident_id: Optional[int] = None
    template_id: Optional[int] = None
    title: str
    message: str
    subject: Optional[str] = None
    channels: List[AlertChannel]
    target_all: bool = False
    target_group_ids: Optional[List[int]] = []
    target_user_ids: Optional[List[int]] = []
    scheduled_at: Optional[datetime] = None
    response_required: bool = False
    response_deadline_minutes: Optional[int] = None
    slack_webhook_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None


class NotificationResponse(BaseModel):
    id: int
    incident_id: Optional[int]
    title: str
    message: str
    subject: Optional[str]
    channels: List[str]
    status: NotificationStatus
    target_all: bool
    scheduled_at: Optional[datetime]
    sent_at: Optional[datetime]
    total_recipients: int
    sent_count: int
    delivered_count: int
    failed_count: int
    response_required: bool
    created_by_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class NotificationDetailResponse(NotificationResponse):
    target_groups: List[GroupResponse]
    delivery_stats: Optional[dict] = None
    response_stats: Optional[dict] = None

    class Config:
        from_attributes = True


class DeliveryLogResponse(BaseModel):
    id: int
    user_id: int
    user_name: Optional[str]
    channel: AlertChannel
    status: DeliveryStatus
    to_address: Optional[str]
    error_message: Optional[str]
    sent_at: Optional[datetime]
    delivered_at: Optional[datetime]

    class Config:
        from_attributes = True


class NotificationResponseCreate(BaseModel):
    """Schema for submitting a safety response to a notification.
    
    Note: notification_id is provided via URL path parameter, not in request body.
    """
    response_type: ResponseType
    message: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class NotificationResponseOut(BaseModel):
    id: int
    notification_id: int
    user_id: Optional[int]
    user_name: Optional[str]
    channel: Optional[AlertChannel]
    response_type: ResponseType
    message: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    responded_at: datetime

    class Config:
        from_attributes = True


# ─── DASHBOARD ────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_users: int
    total_groups: int
    total_locations: int
    active_incidents: int
    notifications_today: int
    notifications_this_week: int
    recent_notifications: List[NotificationResponse]
    recent_incidents: List[IncidentResponse]


# ─── INCOMING MESSAGE ─────────────────────────────────────────────────────────

class IncomingMessageResponse(BaseModel):
    id: int
    from_number: str
    body: Optional[str]
    channel: AlertChannel
    user_id: Optional[int]
    user_name: Optional[str]
    notification_id: Optional[int]
    is_processed: bool
    received_at: datetime


# ─── LOCATION AUDIENCE MANAGEMENT ─────────────────────────────────────────────

class UserLocationAssign(BaseModel):
    """Schema for manually assigning a user to a location."""
    user_id: int
    location_id: int
    notes: Optional[str] = None
    expires_at: Optional[datetime] = None


class UserLocationRemove(BaseModel):
    """Schema for removing a user from a location."""
    reason: Optional[str] = None


class UserLocationGeofenceUpdate(BaseModel):
    """Schema for user location update (geofence detection)."""
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)


class UserLocationResponse(BaseModel):
    """Response schema for user-location assignment."""
    id: int
    user_id: int
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    location_id: int
    location_name: str
    assignment_type: UserLocationAssignmentType
    status: UserLocationStatus
    detected_latitude: Optional[float] = None
    detected_longitude: Optional[float] = None
    distance_from_center_miles: Optional[float] = None
    assigned_by_id: Optional[int] = None
    assigned_by_name: Optional[str] = None
    notes: Optional[str] = None
    assigned_at: datetime
    expires_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserLocationHistoryResponse(BaseModel):
    """Response schema for location membership history."""
    id: int
    user_id: int
    user_name: Optional[str] = None
    location_id: int
    location_name: str
    action: str
    assignment_type: Optional[UserLocationAssignmentType] = None
    previous_status: Optional[UserLocationStatus] = None
    new_status: Optional[UserLocationStatus] = None
    triggered_by_user_id: Optional[int] = None
    triggered_by_name: Optional[str] = None
    reason: Optional[str] = None
    detected_latitude: Optional[float] = None
    detected_longitude: Optional[float] = None
    distance_from_center_miles: Optional[float] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class LocationOverlapInfo(BaseModel):
    """Information about overlapping locations."""
    location_id: int
    location_name: str
    distance_miles: float
    overlap_miles: float
    overlap_percentage: float


class LocationCreateValidated(BaseModel):
    """Validated location creation data."""
    name: str
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: str = "USA"
    latitude: float
    longitude: float
    geofence_radius_miles: float
    overlaps: Optional[List[LocationOverlapInfo]] = None


class GeofenceCheckResult(BaseModel):
    """Result of a geofence check for a single location."""
    location_id: int
    location_name: str
    is_inside: bool
    distance_miles: float
    distance_km: float
    radius_miles: float
    margin_miles: float


class UserGeofenceStatus(BaseModel):
    """User's geofence status across all locations."""
    user_id: int
    latitude: float
    longitude: float
    checked_at: datetime
    locations_inside: List[GeofenceCheckResult]
    locations_outside: List[GeofenceCheckResult]
    assignments_changed: List[Dict[str, Any]] = []


class LocationMemberListResponse(BaseModel):
    """Response for listing location members."""
    total: int
    page: int
    page_size: int
    location_id: int
    location_name: str
    items: List[UserLocationResponse]


class UserLocationHistoryListResponse(BaseModel):
    """Response for listing location membership history."""
    total: int
    page: int
    page_size: int
    items: List[UserLocationHistoryResponse]


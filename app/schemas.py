from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Any
from datetime import datetime
from app.models import (
    UserRole, GroupType, NotificationStatus, DeliveryStatus,
    ResponseType, AlertChannel, IncidentSeverity, IncidentStatus
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


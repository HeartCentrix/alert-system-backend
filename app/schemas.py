import re
from pydantic import BaseModel, EmailStr, Field, validator, field_validator, constr
from typing import Optional, List, Any, Dict, Union
from datetime import datetime
from app.models import (
    UserRole, GroupType, NotificationStatus, DeliveryStatus,
    ResponseType, AlertChannel, IncidentSeverity, IncidentStatus,
    UserLocationAssignmentType, UserLocationStatus
)

# ─── VALIDATION CONSTANTS ─────────────────────────────────────────────────────
# Centralized validation rules for consistency across all schemas

# Name field limits
FIRST_NAME_MAX_LENGTH = 50
LAST_NAME_MAX_LENGTH = 50
FULL_NAME_MAX_LENGTH = 100

# Pattern for names: allow letters (including accented), spaces, hyphens, apostrophes
NAME_PATTERN = r"^[a-zA-Z\u00C0-\u017F\s'-]+$"

# Contact field limits
PHONE_MAX_LENGTH = 20
PHONE_PATTERN = r"^[\d\s()+\-]*$"
EMAIL_MAX_LENGTH = 255

# Department/Title limits
DEPARTMENT_MAX_LENGTH = 100
TITLE_MAX_LENGTH = 100
EMPLOYEE_ID_MAX_LENGTH = 50

# Password limits
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

# MFA/TOTP limits
MFA_CODE_LENGTH = 6
MFA_CODE_PATTERN = r"^\d{6}$"

# Recovery code limits
RECOVERY_CODE_MIN_LENGTH = 10
RECOVERY_CODE_MAX_LENGTH = 20
RECOVERY_CODE_PATTERN = r"^[A-Z0-9\-]+$"

# General text limits
DESCRIPTION_MAX_LENGTH = 500
MESSAGE_MAX_LENGTH = 2000
NAME_FIELD_MAX_LENGTH = 100

# Pagination limits
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20

# Validation error messages
COORDINATES_NAN_ERROR = "Coordinates cannot be NaN or Infinity"
CODE_REQUIRED_MSG = "Code is required"
CODE_FORMAT_MSG = "Code must be exactly 6 digits"
TOTP_DESCRIPTION = "6-digit TOTP code from authenticator app"
CURRENT_PASSWORD_DESCRIPTION = "Current password for reauthentication"
CURRENT_PASSWORD_REQUIRED_MSG = "Current password is required"


# ─── AUTH ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_fingerprint: Optional[str] = None  # Browser-generated device hash for attack detection
    mfa_code: Optional[str] = None  # TOTP code for MFA verification (6 digits)
    # Note: CAPTCHA verification intentionally NOT implemented per security review


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"
    refresh_token: Optional[str] = None  # For cross-origin deployments (Vercel + Railway)


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

    @validator("new_password")
    def validate_password(cls, v):
        from app.core.security import validate_password_strength
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @validator("new_password")
    def validate_password(cls, v):
        from app.core.security import validate_password_strength
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v


class MFASetupInitiateResponse(BaseModel):
    """Response when initiating MFA setup."""
    secret: str
    qr_code_uri: str
    manual_entry_key: str


class MFASetupConfirmRequest(BaseModel):
    """Request to confirm MFA setup with TOTP code."""
    code: str = Field(
        ...,
        min_length=MFA_CODE_LENGTH,
        max_length=MFA_CODE_LENGTH,
        pattern=MFA_CODE_PATTERN,
        description=TOTP_DESCRIPTION
    )

    @field_validator("code")
    @classmethod
    def validate_code_format(cls, v):
        """Ensure code contains only digits and is exactly 6 digits."""
        if not v or not isinstance(v, str):
            raise ValueError(CODE_REQUIRED_MSG)
        code = v.strip()
        if not re.match(r"^\d{6}$", code):
            raise ValueError(CODE_FORMAT_MSG)
        return code


class MFAStatusResponse(BaseModel):
    """Response showing MFA status for a user."""
    mfa_enabled: bool
    mfa_configured: bool  # True if mfa_secret exists


class MFANeededResponse(BaseModel):
    """Response when MFA is required but not configured."""
    mfa_required: bool
    mfa_configured: bool
    secret: str
    qr_code_uri: str
    message: str


class MFAChallengeResponse(BaseModel):
    """Response when MFA is required and already configured."""
    mfa_required: bool
    mfa_configured: bool
    challenge_token: str
    message: str


class LoginSuccessResponse(BaseModel):
    """Standard login success response with tokens."""
    status: str = "success"
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"
    refresh_token: Optional[str] = None  # For cross-origin deployments (Vercel + Railway)
    recovery_codes: Optional[List[str]] = None  # Only present on first MFA setup
    recovery_codes_warning: Optional[str] = None  # Security warning


class LoginMFASetupResponse(BaseModel):
    """MFA setup required - user needs to configure MFA."""
    status: str = "mfa_required"
    mfa_required: bool
    mfa_configured: bool
    challenge_token: str
    qr_code_uri: str
    secret: str
    message: str


class LoginMFAChallengeResponse(BaseModel):
    """MFA challenge - user needs to enter OTP code."""
    status: str = "mfa_required"
    mfa_required: bool
    mfa_configured: bool
    challenge_token: str
    message: str


class MFAVerifyLoginRequest(BaseModel):
    """Request to verify MFA and complete login."""
    challenge_token: str = Field(..., min_length=10, max_length=500)
    code: str = Field(
        ...,
        min_length=MFA_CODE_LENGTH,
        max_length=MFA_CODE_LENGTH,
        pattern=MFA_CODE_PATTERN,
        description=TOTP_DESCRIPTION
    )

    @field_validator("code")
    @classmethod
    def validate_code_format(cls, v):
        """Ensure code contains only digits and is exactly 6 digits."""
        if not v or not isinstance(v, str):
            raise ValueError(CODE_REQUIRED_MSG)
        code = v.strip()
        if not re.match(r"^\d{6}$", code):
            raise ValueError(CODE_FORMAT_MSG)
        return code


class MFARecoveryCodeVerifyRequest(BaseModel):
    """Request to verify a recovery code during login."""
    challenge_token: str = Field(..., min_length=10, max_length=500)
    recovery_code: str = Field(
        ...,
        min_length=RECOVERY_CODE_MIN_LENGTH,
        max_length=RECOVERY_CODE_MAX_LENGTH,
        pattern=RECOVERY_CODE_PATTERN,
        description="Recovery code (alphanumeric with dashes)"
    )

    @field_validator("recovery_code")
    @classmethod
    def validate_recovery_code_format(cls, v):
        """Ensure recovery code has valid format."""
        if not v or not isinstance(v, str):
            raise ValueError("Recovery code is required")
        # Remove spaces and dashes, convert to uppercase
        code = v.strip().replace(" ", "").replace("-", "").upper()
        if len(code) < RECOVERY_CODE_MIN_LENGTH:
            raise ValueError("Recovery code is too short")
        if len(code) > RECOVERY_CODE_MAX_LENGTH:
            raise ValueError("Recovery code is too long")
        # Validate alphanumeric format
        if not re.match(r"^[A-Z0-9]+$", code):
            raise ValueError("Recovery code must contain only letters and numbers")
        return code


class MFARecoveryCodesResponse(BaseModel):
    """Response containing generated recovery codes."""
    recovery_codes: List[str]  # Plaintext codes (shown only once)
    batch_id: str
    message: str
    warning: str  # Security warning about storing codes


class MFARecoveryCodeStatus(BaseModel):
    """Status of user's recovery codes."""
    has_codes: bool
    unused_count: int
    batch_id: Optional[str] = None
    codes_generated_at: Optional[datetime] = None


class MFARegenerateRecoveryCodesRequest(BaseModel):
    """Request to regenerate recovery codes (requires dual-proof: password + MFA).

    Per OWASP/NIST guidance, recovery code regeneration is a high-risk action
    requiring verification of both:
    1. Current password (knowledge factor)
    2. Current MFA proof (possession factor - TOTP or recovery code)

    For privileged users (ADMIN, MANAGER, SUPER_ADMIN):
    - Recovery code fallback is NOT allowed
    - Must use active TOTP from authenticator app

    For normal users:
    - May use TOTP or single unused recovery code (if authenticator unavailable)
    """
    current_password: str = Field(
        ...,
        min_length=1,
        max_length=PASSWORD_MAX_LENGTH,
        description=CURRENT_PASSWORD_DESCRIPTION
    )
    method: str = Field(
        default="totp",
        description="Verification method: 'totp' or 'recovery_code'"
    )
    mfa_code: Optional[str] = Field(
        None,
        min_length=MFA_CODE_LENGTH,
        max_length=MFA_CODE_LENGTH,
        pattern=MFA_CODE_PATTERN,
        description="6-digit TOTP code (required for totp method)"
    )
    recovery_code: Optional[str] = Field(
        None,
        min_length=RECOVERY_CODE_MIN_LENGTH,
        max_length=RECOVERY_CODE_MAX_LENGTH,
        description="Recovery code (required for recovery_code method)"
    )

    @field_validator("current_password")
    @classmethod
    def validate_password_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError(CURRENT_PASSWORD_REQUIRED_MSG)
        return v

    @field_validator("method")
    @classmethod
    def validate_method(cls, v):
        if v not in ["totp", "recovery_code"]:
            raise ValueError("Method must be 'totp' or 'recovery_code'")
        return v

    @field_validator("mfa_code")
    @classmethod
    def validate_mfa_code(cls, v, info):
        method = info.data.get("method")
        if method == "totp":
            if not v or not isinstance(v, str):
                raise ValueError("MFA code is required for TOTP method")
            code = v.strip()
            if not re.match(r"^\d{6}$", code):
                raise ValueError("MFA code must be exactly 6 digits")
        return v

    @field_validator("recovery_code")
    @classmethod
    def validate_recovery_code(cls, v, info):
        method = info.data.get("method")
        if method == "recovery_code":
            if not v or not isinstance(v, str):
                raise ValueError("Recovery code is required for recovery_code method")
            # Remove spaces and dashes, convert to uppercase
            code = v.strip().replace(" ", "").replace("-", "").upper()
            if len(code) < RECOVERY_CODE_MIN_LENGTH:
                raise ValueError("Recovery code is too short")
            if len(code) > RECOVERY_CODE_MAX_LENGTH:
                raise ValueError("Recovery code is too long")
        return v


class MFARegenerateRecoveryCodesResponse(BaseModel):
    """Response after successful recovery code regeneration."""
    recovery_codes: List[str]  # Plaintext codes (shown only once)
    batch_id: str
    message: str
    warning: str  # Security warning about storing codes
    old_codes_invalidated: int  # Number of old codes that were invalidated


# ─── MFA LIFECYCLE MANAGEMENT ────────────────────────────────────────────────

class MFAEnrollStartRequest(BaseModel):
    """Request to start MFA enrollment (requires reauthentication)."""
    current_password: str = Field(
        ...,
        min_length=1,
        max_length=PASSWORD_MAX_LENGTH,
        description=CURRENT_PASSWORD_DESCRIPTION
    )

    @field_validator("current_password")
    @classmethod
    def validate_password_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError(CURRENT_PASSWORD_REQUIRED_MSG)
        return v


class MFAEnrollStartResponse(BaseModel):
    """Response when starting MFA enrollment."""
    secret: str
    qr_code_uri: str
    manual_entry_key: str
    message: str
    # Note: MFA is NOT enabled yet - waiting for OTP verification


class MFAEnrollConfirmRequest(BaseModel):
    """Request to confirm MFA enrollment with TOTP code."""
    code: str = Field(
        ...,
        min_length=MFA_CODE_LENGTH,
        max_length=MFA_CODE_LENGTH,
        pattern=MFA_CODE_PATTERN,
        description=TOTP_DESCRIPTION
    )

    @field_validator("code")
    @classmethod
    def validate_code_format(cls, v):
        """Ensure code contains only digits and is exactly 6 digits."""
        if not v or not isinstance(v, str):
            raise ValueError(CODE_REQUIRED_MSG)
        code = v.strip()
        if not re.match(r"^\d{6}$", code):
            raise ValueError(CODE_FORMAT_MSG)
        return code


class MFAEnrollConfirmResponse(BaseModel):
    """Response after successful MFA enrollment."""
    message: str
    recovery_codes: List[str]  # Shown only once
    recovery_codes_warning: str


class MFADisableRequest(BaseModel):
    """Request to disable MFA (requires reauthentication + current factor)."""
    current_password: str = Field(
        ...,
        min_length=1,
        max_length=PASSWORD_MAX_LENGTH,
        description=CURRENT_PASSWORD_DESCRIPTION
    )
    mfa_code: str = Field(
        ...,
        min_length=6,
        max_length=20,
        description="Current TOTP code or recovery code"
    )

    @field_validator("current_password")
    @classmethod
    def validate_password_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError(CURRENT_PASSWORD_REQUIRED_MSG)
        return v

    @field_validator("mfa_code")
    @classmethod
    def validate_mfa_code(cls, v):
        """Validate MFA code format - allows both TOTP (6 digits) and recovery codes."""
        if not v or not isinstance(v, str):
            raise ValueError("MFA code is required")
        code = v.strip()
        if len(code) < 6:
            raise ValueError("Invalid MFA code format")
        return code


class MFADisableResponse(BaseModel):
    """Response after successfully disabling MFA."""
    message: str
    mfa_disabled: bool


class MFAResetStartRequest(BaseModel):
    """Request to reset/replace MFA (requires reauthentication + current factor)."""
    current_password: str = Field(
        ...,
        min_length=1,
        max_length=PASSWORD_MAX_LENGTH,
        description=CURRENT_PASSWORD_DESCRIPTION
    )
    mfa_code: str = Field(
        ...,
        min_length=6,
        max_length=20,
        description="Current TOTP code or recovery code"
    )

    @field_validator("current_password")
    @classmethod
    def validate_password_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError(CURRENT_PASSWORD_REQUIRED_MSG)
        return v


class MFAResetConfirmRequest(BaseModel):
    """Request to confirm MFA reset with new TOTP code."""
    code: str = Field(
        ...,
        min_length=MFA_CODE_LENGTH,
        max_length=MFA_CODE_LENGTH,
        pattern=MFA_CODE_PATTERN,
        description=TOTP_DESCRIPTION
    )

    @field_validator("code")
    @classmethod
    def validate_code_format(cls, v):
        """Ensure code contains only digits and is exactly 6 digits."""
        if not v or not isinstance(v, str):
            raise ValueError(CODE_REQUIRED_MSG)
        code = v.strip()
        if not re.match(r"^\d{6}$", code):
            raise ValueError(CODE_FORMAT_MSG)
        return code


class MFAResetConfirmResponse(BaseModel):
    """Response after successful MFA reset/re-enrollment."""
    message: str
    recovery_codes: List[str]  # New recovery codes (shown only once)
    recovery_codes_warning: str


class MFAReauthenticateRequest(BaseModel):
    """Request for step-up reauthentication before sensitive MFA operations."""
    current_password: str

    @validator("current_password")
    def validate_password_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError(CURRENT_PASSWORD_REQUIRED_MSG)
        return v


class MFAReauthenticateResponse(BaseModel):
    """Response after successful reauthentication."""
    reauth_token: str  # Short-lived token for MFA operations
    expires_in: int  # Seconds until token expires
    message: str


class MFAStatusDetailResponse(BaseModel):
    """Enhanced MFA status response for security settings."""
    mfa_enabled: bool
    mfa_required: bool  # True if user's role requires MFA
    mfa_configured: bool  # True if mfa_secret exists
    has_recovery_codes: bool
    recovery_codes_count: int  # Number of unused codes (not the codes themselves)
    can_disable: bool  # Whether user is allowed to disable MFA
    pending_enrollment: bool  # True if user started but didn't complete enrollment


# ─── ADMIN MFA MANAGEMENT ───────────────────────────────────────────────────

class AdminMFAStatusResponse(BaseModel):
    """Admin view of user's MFA status (safe metadata only)."""
    user_id: int
    user_email: str
    mfa_enabled: bool
    mfa_required: bool
    mfa_configured: bool
    has_recovery_codes: bool
    recovery_codes_count: int
    role: str


class AdminMFAResetRequest(BaseModel):
    """Admin request to reset user's MFA."""
    reason: str = "admin_assisted_reset"  # Required reason for audit

    @validator("reason")
    def validate_reason_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("Reason is required for admin MFA reset")
        return v


class AdminMFAResetResponse(BaseModel):
    """Response after admin resets user's MFA."""
    message: str
    mfa_reset: bool
    user_notified: bool
    reason: str


# Union type for login responses - use Any for now, FastAPI will handle it
# In production, consider using typing.Union with FastAPI's response_model


# ─── USER ─────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr = Field(..., max_length=EMAIL_MAX_LENGTH)
    password: str = Field(
        ...,
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
        description="User password (must meet strength requirements)"
    )
    first_name: str = Field(
        ...,
        min_length=1,
        max_length=FIRST_NAME_MAX_LENGTH,
        pattern=NAME_PATTERN,
        description="User's first name"
    )
    last_name: str = Field(
        ...,
        min_length=1,
        max_length=LAST_NAME_MAX_LENGTH,
        pattern=NAME_PATTERN,
        description="User's last name"
    )
    phone: Optional[str] = Field(
        None,
        max_length=PHONE_MAX_LENGTH,
        pattern=PHONE_PATTERN,
        description="Phone number (digits, spaces, +, (), -)"
    )
    department: Optional[str] = Field(
        None,
        max_length=DEPARTMENT_MAX_LENGTH,
        description="Department name"
    )
    title: Optional[str] = Field(
        None,
        max_length=TITLE_MAX_LENGTH,
        description="Job title"
    )
    employee_id: Optional[str] = Field(
        None,
        max_length=EMPLOYEE_ID_MAX_LENGTH,
        description="Employee ID"
    )
    role: UserRole = UserRole.VIEWER
    location_id: Optional[int] = None
    preferred_channels: List[AlertChannel] = [AlertChannel.SMS, AlertChannel.EMAIL]

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v):
        from app.core.security import validate_password_strength
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_name_fields(cls, v):
        """Ensure name fields are not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError("This field cannot be empty")
        return v.strip()


class UserUpdate(BaseModel):
    first_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=FIRST_NAME_MAX_LENGTH,
        pattern=NAME_PATTERN
    )
    last_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=LAST_NAME_MAX_LENGTH,
        pattern=NAME_PATTERN
    )
    phone: Optional[str] = Field(
        None,
        max_length=PHONE_MAX_LENGTH,
        pattern=PHONE_PATTERN
    )
    department: Optional[str] = Field(
        None,
        max_length=DEPARTMENT_MAX_LENGTH
    )
    title: Optional[str] = Field(
        None,
        max_length=TITLE_MAX_LENGTH
    )
    employee_id: Optional[str] = Field(
        None,
        max_length=EMPLOYEE_ID_MAX_LENGTH
    )
    email: Optional[EmailStr] = Field(
        None,
        max_length=EMAIL_MAX_LENGTH
    )
    role: Optional[UserRole] = None
    location_id: Optional[int] = None
    is_active: Optional[bool] = None
    preferred_channels: Optional[List[AlertChannel]] = None

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_name_fields_optional(cls, v):
        """Ensure optional name fields are not whitespace-only when provided."""
        if v is not None and not v.strip():
            raise ValueError("This field cannot be empty or whitespace-only")
        return v.strip() if v else v


class UserProfileUpdate(BaseModel):
    """Schema for users to update their own profile.

    Restricts updating sensitive fields like role, is_active, employee_id.
    """
    first_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=FIRST_NAME_MAX_LENGTH,
        pattern=NAME_PATTERN
    )
    last_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=LAST_NAME_MAX_LENGTH,
        pattern=NAME_PATTERN
    )
    phone: Optional[str] = Field(
        None,
        max_length=PHONE_MAX_LENGTH,
        pattern=PHONE_PATTERN
    )
    department: Optional[str] = Field(
        None,
        max_length=DEPARTMENT_MAX_LENGTH
    )
    title: Optional[str] = Field(
        None,
        max_length=TITLE_MAX_LENGTH
    )
    location_id: Optional[int] = None
    preferred_channels: Optional[List[AlertChannel]] = None

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_name_fields_optional(cls, v):
        """Ensure optional name fields are not whitespace-only when provided."""
        if v is not None and not v.strip():
            raise ValueError("This field cannot be empty or whitespace-only")
        return v.strip() if v else v


class UserResponse(BaseModel):
    id: int
    email: str
    first_name: str
    last_name: str
    full_name: str
    phone: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    employee_id: Optional[str] = None
    role: UserRole
    is_active: bool
    location_id: Optional[int] = None
    preferred_channels: Optional[List[str]] = None
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
    # List of newly created users (passwords excluded for security, sent via email)
    created_users: List[dict] = []  # [{email, first_name, last_name}, ...]


class UserBulkDeleteResponse(BaseModel):
    deleted: int
    failed: int
    deleted_ids: List[int]
    failed_ids: List[int]


class HeartbeatResponse(BaseModel):
    """Response for user heartbeat endpoint."""
    status: str
    message: str
    last_seen_at: datetime


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

    @field_validator("latitude", "longitude")
    @classmethod
    def validate_coordinates_not_nan(cls, v: Optional[float]) -> Optional[float]:
        """Ensure latitude/longitude are not NaN or Infinity."""
        if v is not None:
            import math
            if math.isnan(v) or math.isinf(v):
                raise ValueError(COORDINATES_NAN_ERROR)
        return v


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

    @field_validator("latitude", "longitude")
    @classmethod
    def validate_coordinates_not_nan(cls, v: Optional[float]) -> Optional[float]:
        """Ensure latitude/longitude are not NaN or Infinity."""
        if v is not None:
            import math
            if math.isnan(v) or math.isinf(v):
                raise ValueError(COORDINATES_NAN_ERROR)
        return v


class LocationResponse(BaseModel):
    id: int
    name: str
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
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
    description: Optional[str] = None
    type: GroupType
    location_id: Optional[int] = None
    dynamic_filter: Optional[dict] = None
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
    category: Optional[str] = None
    subject: Optional[str] = None
    body: str
    channels: List[str]
    variables: Optional[List[dict]] = None
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
    type: Optional[str] = None
    severity: IncidentSeverity
    status: IncidentStatus
    description: Optional[str] = None
    location_id: Optional[int] = None
    created_by_id: int
    resolved_at: Optional[datetime] = None
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
    scheduled_timezone: Optional[str] = None  # Timezone for scheduled time (e.g., "America/New_York")
    response_required: bool = False
    response_deadline_minutes: Optional[int] = None
    slack_webhook_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None


class NotificationResponse(BaseModel):
    id: int
    incident_id: Optional[int] = None
    title: str
    message: str
    subject: Optional[str] = None
    channels: List[str]
    status: NotificationStatus
    target_all: bool
    scheduled_at: Optional[datetime] = None
    sent_at: Optional[datetime] = None
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
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    channel: AlertChannel
    status: DeliveryStatus
    to_address: Optional[str] = None
    error_message: Optional[str] = None
    sent_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class NotificationResponseCreate(BaseModel):
    """Schema for submitting a safety response to a notification.

    Note: notification_id is provided via URL path parameter (/notifications/{id}/respond),
    not in the request body. This follows RESTful design patterns.

    Example request: POST /notifications/123/respond
    Body: {"response_type": "safe", "latitude": 40.7128, "longitude": -74.0060}
    """
    response_type: ResponseType
    message: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    @field_validator("latitude", "longitude")
    @classmethod
    def validate_coordinates_not_nan(cls, v: Optional[float]) -> Optional[float]:
        """Ensure latitude/longitude are not NaN or Infinity."""
        if v is not None:
            import math
            if math.isnan(v) or math.isinf(v):
                raise ValueError(COORDINATES_NAN_ERROR)
        return v


class NotificationResponseOut(BaseModel):
    id: int
    notification_id: int
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    channel: Optional[AlertChannel] = None
    response_type: ResponseType
    message: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    responded_at: datetime

    class Config:
        from_attributes = True


# ─── DASHBOARD ────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_users: int
    online_users: int
    total_groups: int
    total_locations: int
    active_incidents: int
    notifications_today: int
    notifications_this_week: int
    recent_notifications: List[NotificationResponse]
    recent_incidents: List[IncidentResponse]


# ─── INCOMING MESSAGE ─────────────────────────────────────────────────────────

class IncomingMessageResponse(BaseModel):
    id: Union[int, str]  # Can be int for SMS or string for voice responses (e.g., "voice_7")
    from_number: str
    body: Optional[str] = None
    channel: AlertChannel
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    notification_id: Optional[int] = None
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


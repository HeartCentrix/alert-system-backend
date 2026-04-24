from pydantic import field_validator
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "TM Alert"
    APP_ENV: str = "development"
    SECRET_KEY: str = ""
    REFRESH_SECRET_KEY: str = ""
    MFA_CHALLENGE_SECRET_KEY: str = ""
    # Dedicated key for safety check-in tokens so rotating SECRET_KEY in
    # response to a leaked check-in link does not also invalidate every
    # active access/session token. Falls back to SECRET_KEY so existing
    # deployments keep working until a distinct key is provisioned
    # (security review B-M2).
    CHECKIN_SECRET_KEY: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    FRONTEND_URL: str = "http://localhost:3000"
    BACKEND_URL: str = "http://localhost:8000"

    DATABASE_URL: str = "postgresql://postgres:password@localhost:5432/tm_alert"
    REDIS_URL: str = "redis://localhost:6379/0"

    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_FROM_NUMBER: str = ""

    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = "us-east-1"
    SES_FROM_EMAIL: str = "noreply@tmalert.com"
    SES_FROM_NAME: str = "TM Alert"

    # SMTP settings for async email notifications
    EMAIL_FROM: str = "security@tmalert.com"
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""

    GOOGLE_MAPS_API_KEY: str = ""

    # ── Geocoding Provider ────────────────────────────────────────────
    # "photon_public"  → photon.komoot.io  (free, no key, global)
    # "photon_self"    → your own Photon instance
    GEOCODING_PROVIDER: str = "photon_public"
    GEOCODING_PROVIDER_URL: str = ""

    # LocationIQ API key (optional - for geocoding fallback)
    LOCATIONIQ_API_KEY: str = ""

    # MFA/2FA settings
    # TOTP valid window: 0 = current step only (most secure), 1 = allow one step for clock skew
    # RFC 6237 recommends at most one time step; 0 is preferred for security
    MFA_TOTP_VALID_WINDOW: int = 0

    # MFA encryption key for encrypting MFA secrets at rest (Fernet key)
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    MFA_ENCRYPTION_KEY: str = ""

    # Test database/redis URLs (used in CI/CD testing)
    TEST_DATABASE_URL: Optional[str] = None
    TEST_REDIS_URL: Optional[str] = None

    # ── Authentication Providers ───────────────────────────────────────
    # Comma-separated list of enabled auth providers: local, entra, ldap
    # "local" = email+password (current), "entra" = Microsoft Entra ID, "ldap" = on-prem AD
    AUTH_PROVIDERS: str = "local"

    # Microsoft Entra ID (Azure AD) — OAuth 2.0 / OIDC
    ENTRA_ENABLED: bool = False
    ENTRA_CLIENT_ID: str = ""
    ENTRA_CLIENT_SECRET: str = ""
    ENTRA_TENANT_ID: str = ""  # Specific tenant ID, or "common" for multi-tenant
    ENTRA_REDIRECT_URI: str = ""  # https://your-backend.railway.app/api/v1/auth/entra/callback
    ENTRA_SCOPES: str = "openid profile email"  # Space-separated OIDC scopes

    # On-prem LDAP / Active Directory
    LDAP_ENABLED: bool = False
    LDAP_SERVER_URL: str = ""  # ldaps://ad.company.com:636 (always use ldaps://)
    LDAP_BIND_DN: str = ""  # Service account DN for searching
    LDAP_BIND_PASSWORD: str = ""
    LDAP_USER_SEARCH_BASE: str = ""  # ou=Users,dc=company,dc=com
    LDAP_USER_SEARCH_FILTER: str = "(&(objectClass=user)(sAMAccountName={username}))"
    LDAP_EMAIL_ATTRIBUTE: str = "mail"
    LDAP_FIRST_NAME_ATTRIBUTE: str = "givenName"
    LDAP_LAST_NAME_ATTRIBUTE: str = "sn"
    LDAP_GROUP_SEARCH_BASE: str = ""  # Optional: ou=Groups,dc=company,dc=com
    LDAP_REQUIRED_GROUP: str = ""  # Optional: cn=TM-Alert-Users,ou=Groups,dc=company,dc=com
    LDAP_USE_TLS: bool = True

    # User provisioning
    AUTO_PROVISION_USERS: bool = True  # Auto-create users on first SSO/LDAP login
    ALLOWED_EMAIL_DOMAINS: str = ""  # Comma-separated: company.com,subsidiary.com (empty = allow all)

    # Comma-separated emails exempted from role-based MFA enforcement.
    # ONLY honoured when APP_ENV=development. The check in
    # app.core.security.user_requires_mfa refuses the exemption in any
    # other environment, so setting this in prod has no effect.
    MFA_EXEMPT_EMAILS: str = ""

    # Refuse to boot with empty signing secrets. Defaults of "" would let
    # every JWT (access, refresh, MFA challenge) be signed with the empty
    # HMAC key if the operator forgot to set them, turning deployment into
    # a complete auth bypass (security review B-C1 / B-C2). CHECKIN_SECRET_KEY
    # is intentionally allowed to be empty because app/utils/checkin_link.py
    # falls back to SECRET_KEY, which this validator guarantees is set.
    @field_validator("SECRET_KEY", "REFRESH_SECRET_KEY", "MFA_CHALLENGE_SECRET_KEY")
    @classmethod
    def _require_non_empty_secret(cls, v: str, info) -> str:
        if not v or not v.strip():
            raise ValueError(
                f"{info.field_name} must be a non-empty random string. "
                f"Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = 'ignore'  # Ignore extra environment variables in CI


settings = Settings()


def _validate_auth_provider_safety() -> None:
    """
    Refuse to start with an auth configuration that silently admits any
    Microsoft account / any LDAP identity. Security review B-H4 / M6.

    Rules:
      - If ENTRA_ENABLED is on and the tenant is 'common' (multi-tenant,
        effectively anyone with an MS account can sign in), at least one
        allow-listed email domain must be configured, otherwise any Azure
        user self-provisions as a VIEWER on first login.
      - If AUTO_PROVISION_USERS is on for any external provider, an email
        domain allow-list is required.
    """
    providers = {p.strip().lower() for p in settings.AUTH_PROVIDERS.split(",") if p.strip()}
    allowed_domains_set = any(
        d.strip() for d in settings.ALLOWED_EMAIL_DOMAINS.split(",") if d.strip()
    )
    external_providers_enabled = (
        ("entra" in providers and settings.ENTRA_ENABLED)
        or ("ldap" in providers and settings.LDAP_ENABLED)
    )

    if settings.ENTRA_ENABLED and (not settings.ENTRA_TENANT_ID or settings.ENTRA_TENANT_ID.lower() == "common"):
        if not allowed_domains_set:
            raise RuntimeError(
                "Unsafe Entra configuration: ENTRA_TENANT_ID is unset or 'common' "
                "(accepts any Microsoft tenant) and ALLOWED_EMAIL_DOMAINS is empty. "
                "Set ENTRA_TENANT_ID to a specific tenant GUID or populate "
                "ALLOWED_EMAIL_DOMAINS with at least one domain before starting."
            )

    if external_providers_enabled and settings.AUTO_PROVISION_USERS and not allowed_domains_set:
        raise RuntimeError(
            "Unsafe auth configuration: AUTO_PROVISION_USERS=True with at least "
            "one external provider enabled and ALLOWED_EMAIL_DOMAINS empty. Any "
            "successful Entra/LDAP login would create a real VIEWER account. "
            "Set ALLOWED_EMAIL_DOMAINS or disable AUTO_PROVISION_USERS."
        )


_validate_auth_provider_safety()

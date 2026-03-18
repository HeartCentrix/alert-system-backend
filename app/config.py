from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "TM Alert"
    APP_ENV: str = "development"
    SECRET_KEY: str = ""
    REFRESH_SECRET_KEY: str = ""
    MFA_CHALLENGE_SECRET_KEY: str = ""
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

    SLACK_DEFAULT_WEBHOOK_URL: str = ""
    TEAMS_DEFAULT_WEBHOOK_URL: str = ""

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

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = 'ignore'  # Ignore extra environment variables in CI


settings = Settings()

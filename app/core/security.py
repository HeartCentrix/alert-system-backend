from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import jwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from app.config import settings
import re
import pyotp
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet, InvalidToken
import logging

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"

# Password policy constants
MIN_PASSWORD_LENGTH = 8

# MFA policy constants - roles that always require MFA
# SUPER_ADMIN, ADMIN, and MANAGER must always use MFA
MFA_REQUIRED_ROLES = ["super_admin", "admin", "manager"]

# Reauthentication TTL for sensitive MFA operations (5 minutes)
MFA_REAUTH_TTL_SECONDS = 300

# Fernet encryption for MFA secrets
# Lazy initialization to avoid issues if key is missing
_mfa_fernet: Optional[Fernet] = None


def _get_mfa_fernet() -> Optional[Fernet]:
    """
    Get or create the Fernet instance for MFA encryption.
    
    Returns None if MFA_ENCRYPTION_KEY is not configured.
    """
    global _mfa_fernet
    if _mfa_fernet is not None:
        return _mfa_fernet
    
    if not settings.MFA_ENCRYPTION_KEY:
        logger.warning("MFA_ENCRYPTION_KEY not configured. MFA secrets will NOT be encrypted.")
        return None
    
    try:
        _mfa_fernet = Fernet(settings.MFA_ENCRYPTION_KEY.encode())
        return _mfa_fernet
    except Exception as e:
        logger.error(f"Failed to initialize MFA Fernet encryption: {e}")
        return None


def encrypt_mfa_secret(secret: str) -> str:
    """
    Encrypt an MFA secret using Fernet symmetric encryption.
    
    Args:
        secret: Plaintext base32-encoded TOTP secret
        
    Returns:
        Encrypted secret (Fernet token) or original secret if encryption unavailable
        
    Security:
        - Fernet provides authenticated encryption (AES-CBC + HMAC)
        - Tokens include timestamp for potential rotation
        - Encrypted tokens start with 'gAAAAA' (base64 encoding of version byte)
    """
    fernet = _get_mfa_fernet()
    if not fernet:
        # Encryption not configured, return plaintext (backward compatibility)
        return secret
    
    try:
        encrypted = fernet.encrypt(secret.encode('utf-8'))
        return encrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to encrypt MFA secret: {e}")
        # Fail closed: return plaintext rather than breaking MFA entirely
        # This is a security tradeoff; in high-security environments, raise instead
        return secret


def decrypt_mfa_secret(encrypted_secret: str) -> Optional[str]:
    """
    Decrypt an MFA secret.
    
    Handles both encrypted and plaintext secrets for backward compatibility.
    
    Args:
        encrypted_secret: Encrypted or plaintext MFA secret
        
    Returns:
        Decrypted plaintext secret, or None if decryption fails
        
    Security:
        - Detects plaintext vs encrypted by Fernet token prefix (gAAAAA)
        - Returns None on decryption failure (invalid key or corrupted token)
        - Logs decryption failures for security monitoring
    """
    fernet = _get_mfa_fernet()
    
    # Check if this is an encrypted secret (Fernet tokens start with 'gAAAAA')
    if not encrypted_secret.startswith('gAAAAA'):
        # Plaintext secret (old format or encryption not enabled)
        # Return as-is for backward compatibility
        return encrypted_secret
    
    if not fernet:
        logger.error("MFA secret is encrypted but MFA_ENCRYPTION_KEY not configured")
        return None
    
    try:
        decrypted = fernet.decrypt(encrypted_secret.encode('utf-8'))
        return decrypted.decode('utf-8')
    except InvalidToken:
        logger.error("Failed to decrypt MFA secret - invalid token or wrong encryption key")
        return None
    except Exception as e:
        logger.error(f"Failed to decrypt MFA secret: {e}")
        return None


def hash_password_reset_token(token: str) -> str:
    """
    Hash a password reset token using SHA-256.
    
    Password reset tokens are stored as hashes to prevent database leaks
    from being usable for password resets.
    
    Args:
        token: Plaintext reset token (sent to user via email)
        
    Returns:
        SHA-256 hash of the token (64-character hex string)
        
    Security:
        - SHA-256 is sufficient for random tokens (no need for bcrypt)
        - Tokens are high-entropy (secrets.token_urlsafe(32))
        - Hash is stored in DB, plaintext only in email/URL
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def verify_password_reset_token(plaintext_token: str, hashed_token: str) -> bool:
    """
    Verify a password reset token against its stored hash.
    
    Args:
        plaintext_token: Token provided by user (from email/URL)
        hashed_token: Hash stored in database
        
    Returns:
        True if token matches, False otherwise
        
    Security:
        - Uses constant-time comparison via hmac.compare_digest
        - Prevents timing attacks
    """
    import hmac
    computed_hash = hash_password_reset_token(plaintext_token)
    return hmac.compare_digest(computed_hash, hashed_token)


def user_requires_mfa(user) -> bool:
    """
    Determine if a user requires MFA based on policy.

    MFA is required if:
    - user.mfa_enabled is True, OR
    - user role is ADMIN or MANAGER (privileged roles)

    This centralizes MFA policy enforcement for consistent behavior.

    Args:
        user: User model instance

    Returns:
        True if MFA is required, False otherwise
    """
    if user.mfa_enabled:
        return True

    # Check if user has a privileged role that always requires MFA
    # Convert role enum to string for comparison
    user_role = str(user.role.value) if hasattr(user.role, 'value') else str(user.role)
    if user_role.lower() in MFA_REQUIRED_ROLES:
        return True

    return False


def can_user_self_disable_mfa(user) -> bool:
    """
    Determine if a user is allowed to self-disable MFA.

    Policy:
    - Privileged users (ADMIN, MANAGER, SUPER_ADMIN) CANNOT self-disable
    - Normal users (VIEWER) can disable if they have MFA enabled

    Args:
        user: User model instance

    Returns:
        True if user can self-disable MFA, False otherwise
    """
    if not user.mfa_enabled:
        return False  # Can't disable what isn't enabled

    user_role = str(user.role.value) if hasattr(user.role, 'value') else str(user.role)
    if user_role.lower() in MFA_REQUIRED_ROLES:
        return False  # Privileged users cannot self-disable

    return True  # Normal users can disable


def can_user_reset_mfa(user) -> bool:
    """
    Determine if a user can reset/re-enroll their MFA.

    All authenticated users can reset their own MFA, but:
    - Privileged users will be forced to re-enroll immediately
    - Normal users follow standard reset flow

    Args:
        user: User model instance

    Returns:
        True if user can reset MFA, False otherwise
    """
    return user.is_active  # All active users can reset


def requires_recent_reauth_for_mfa_change(user, action: str) -> bool:
    """
    Determine if an MFA operation requires recent reauthentication.

    All sensitive MFA operations require step-up authentication:
    - enroll: Starting MFA enrollment
    - disable: Disabling MFA
    - reset: Resetting/replacing MFA
    - regenerate_codes: Regenerating recovery codes

    Args:
        user: User model instance
        action: One of 'enroll', 'disable', 'reset', 'regenerate_codes'

    Returns:
        True if recent reauthentication is required
    """
    # All MFA lifecycle changes require reauthentication
    # This is per OWASP recommendation to not rely on active session alone
    return True


def get_mfa_policy_info(user) -> dict:
    """
    Get MFA policy information for a user.

    Returns policy details for UI display and enforcement.

    Args:
        user: User model instance

    Returns:
        Dict with policy information
    """
    user_role = str(user.role.value) if hasattr(user.role, 'value') else str(user.role)
    is_privileged = user_role.lower() in MFA_REQUIRED_ROLES

    return {
        "mfa_required": is_privileged or user.mfa_enabled,
        "mfa_enforced": is_privileged,  # Cannot be disabled by user
        "can_self_disable": not is_privileged and user.mfa_enabled,
        "can_reset": user.is_active,
        "role": user_role,
    }


def get_recovery_code_regeneration_policy(user) -> dict:
    """
    Get policy for recovery code regeneration.

    Per OWASP and NIST guidance, recovery code regeneration is a
    security-sensitive action requiring dual-factor verification.

    Policy:
    - All MFA-enabled users require password + current MFA proof
    - Privileged users (ADMIN, MANAGER, SUPER_ADMIN) require password + active MFA
    - Privileged users cannot use recovery code fallback in normal regeneration
    - Normal users may use recovery code fallback only if explicitly allowed

    Args:
        user: User model instance

    Returns:
        Dict with regeneration policy information
    """
    user_role = str(user.role.value) if hasattr(user.role, 'value') else str(user.role)
    is_privileged = user_role.lower() in MFA_REQUIRED_ROLES
    is_mfa_enabled = user.mfa_enabled

    # Determine allowed verification methods
    allowed_methods = []
    if is_mfa_enabled and user.mfa_secret:
        allowed_methods.append("totp")  # TOTP from authenticator app

    # Recovery code fallback policy
    allows_recovery_code_fallback = False
    if is_mfa_enabled and not is_privileged:
        # Normal users may use recovery code fallback (when authenticator unavailable)
        allows_recovery_code_fallback = True

    return {
        "requires_password": True,
        "requires_mfa_proof": is_mfa_enabled,  # MFA-enabled users must provide MFA proof
        "allowed_methods": allowed_methods,
        "allows_recovery_code_fallback": allows_recovery_code_fallback,
        "is_privileged": is_privileged,
        "is_mfa_enabled": is_mfa_enabled,
        "requires_strict_verification": is_privileged or is_mfa_enabled,
    }


def verify_totp_code(secret: str, code: str, valid_window: Optional[int] = None) -> bool:
    """
    Verify a TOTP code against a stored secret.
    
    Automatically handles both encrypted and plaintext secrets.

    Args:
        secret: Base32-encoded TOTP secret (may be encrypted with Fernet)
        code: TOTP code to verify
        valid_window: Number of time steps to allow for clock drift
                     If None, uses settings.MFA_TOTP_VALID_WINDOW (default 0)
                     0 = current step only (most secure)
                     1 = allow one previous/next step (for clock skew tolerance)

    Returns:
        True if code is valid, False otherwise

    Security Notes:
        - Does not log secret or code
        - Fails closed on exceptions
        - Uses constant-time comparison via pyotp
        - Default valid_window=0 rejects expired codes (current step only)
        - RFC 6238 warns that larger windows increase attack surface
        - Automatically decrypts Fernet-encrypted secrets
    """
    if not secret or not code:
        return False

    try:
        # Normalize the code - strip whitespace
        code = str(code).strip()

        # Validate code format - must be 6 digits
        if not re.match(r"^\d{6}$", code):
            return False

        # Decrypt secret if it's encrypted (Fernet tokens start with 'gAAAAA')
        decrypted_secret = decrypt_mfa_secret(secret)
        if not decrypted_secret:
            # Decryption failed (wrong key or corrupted token)
            return False

        # Validate secret is valid Base32
        # pyotp handles padding internally, but we normalize here
        decrypted_secret = decrypted_secret.upper().replace(" ", "")

        # Use provided window or fall back to config default
        if valid_window is None:
            valid_window = settings.MFA_TOTP_VALID_WINDOW

        totp = pyotp.TOTP(decrypted_secret)
        return totp.verify(code, valid_window=valid_window)

    except (ValueError, Exception):
        # Fail closed on any exception during verification
        # pyotp may raise various exceptions (binascii.Error, etc.)
        return False


def generate_mfa_secret() -> str:
    """
    Generate a new random TOTP secret for MFA setup.

    Returns:
        Base32-encoded random secret (16 characters)
    """
    return pyotp.random_base32()


def generate_mfa_qr_code_uri(email: str, secret: str, issuer: str = "TM Alert") -> str:
    """
    Generate the provisioning URI for QR code generation.

    This URI can be passed to QR code generators to create scannable
    MFA setup codes for authenticator apps.

    Args:
        email: User's email address (will be shown in authenticator app)
        secret: Base32-encoded TOTP secret
        issuer: Service name to display in authenticator app

    Returns:
        Google Authenticator compatible provisioning URI
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one digit
    - At least one symbol (special character)
    - Not a commonly used weak password (zxcvbn check)
    
    Returns:
        Tuple of (is_valid, error_message)
        error_message is empty string if valid
    """
    # Check minimum length
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
    
    # Check for uppercase letter
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    # Check for digit
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    
    # Check for symbol/special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'`~]", password):
        return False, "Password must contain at least one special character"
    
    # Check against common weak passwords using zxcvbn
    try:
        from zxcvbn import zxcvbn
        result = zxcvbn(password)
        # zxcvbn scores 0-4; require score >= 3 (hard to crack)
        if result["score"] < 3:
            feedback = result.get("feedback", {}).get("warning", "Password is too weak")
            return False, f"Weak password: {feedback}"
    except ImportError:
        # zxcvbn not installed, skip this check
        pass
    
    return True, ""


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "access",
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.REFRESH_SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str, token_type: str = "access") -> Optional[dict]:
    """
    Decode and validate a JWT token.

    Args:
        token: The JWT token to decode
        token_type: Expected token type ('access' or 'refresh')

    Returns:
        Decoded payload if valid, None otherwise
    """
    try:
        # Use appropriate secret key based on token type
        secret_key = settings.SECRET_KEY if token_type == "access" else settings.REFRESH_SECRET_KEY
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])

        # Verify token type matches
        if payload.get("type") != token_type:
            return None

        return payload
    except PyJWTError:
        return None

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.config import settings
import re

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"

# Password policy constants
MIN_PASSWORD_LENGTH = 8


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
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
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
    except JWTError:
        return None

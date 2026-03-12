"""
Check-in Link Generator for Safety Response System

Generates secure, signed URLs for employees to respond to safety check-in requests.
Uses JWT tokens with expiration to prevent unauthorized responses.
"""

import jwt
from datetime import datetime, timezone, timedelta
from typing import Optional
from app.config import settings

# Use SECRET_KEY for signing check-in tokens
# Tokens have a limited lifetime based on the notification deadline


def generate_checkin_token(notification_id: int, user_id: int, deadline_minutes: Optional[int] = None) -> str:
    """
    Generate a signed JWT token for a safety check-in link.
    
    Args:
        notification_id: The notification ID this response is for
        user_id: The user ID who can respond
        deadline_minutes: Optional deadline in minutes (token expires at deadline)
    
    Returns:
        Signed JWT token string
    """
    # Token expires at deadline, or default to 24 hours if no deadline specified
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=deadline_minutes if deadline_minutes else 1440)
    
    payload = {
        "notification_id": notification_id,
        "user_id": user_id,
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
        "type": "safety_checkin"
    }
    
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return token


def verify_checkin_token(token: str) -> Optional[dict]:
    """
    Verify and decode a check-in token.
    
    Args:
        token: The JWT token to verify
    
    Returns:
        Decoded payload if valid, None if invalid or expired
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        
        # Verify token type
        if payload.get("type") != "safety_checkin":
            return None
        
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def generate_checkin_url(notification_id: int, user_id: int, deadline_minutes: Optional[int] = None) -> str:
    """
    Generate a full check-in URL for a user to respond to a safety notification.
    
    Args:
        notification_id: The notification ID
        user_id: The user ID
        deadline_minutes: Optional deadline in minutes
    
    Returns:
        Full URL string for the check-in page
    """
    token = generate_checkin_token(notification_id, user_id, deadline_minutes)
    # Frontend route: /notifications/{id}/respond?token={token}
    return f"{settings.FRONTEND_URL}/notifications/{notification_id}/respond?token={token}"

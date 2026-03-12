"""
Audit log helper utilities.

Provides a consistent way to extract request context (IP, user agent)
for audit log entries across all endpoints.
"""

from typing import Optional
from fastapi import Request
from app.models import AuditLog


def create_audit_log(
    user_id: Optional[int],
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[int] = None,
    details: Optional[dict] = None,
    user_email: Optional[str] = None,
    request: Optional[Request] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> AuditLog:
    """
    Create an AuditLog with consistent request context extraction.
    
    If a Request object is provided, ip_address and user_agent are
    automatically extracted from it. Explicit ip_address/user_agent
    values take precedence (useful for Celery tasks where there's
    no Request object).
    
    Args:
        user_id: ID of the user performing the action
        action: Action name (e.g., "create_user", "send_notification")
        resource_type: Type of resource affected (e.g., "user", "notification")
        resource_id: ID of the resource affected
        details: Additional context as a JSON-serializable dict
        user_email: User's email (preserved after user deletion)
        request: FastAPI Request object (for IP and user-agent extraction)
        ip_address: Override IP address (e.g., from Celery task context)
        user_agent: Override user agent (e.g., from Celery task context)
        
    Returns:
        AuditLog instance ready to be added to a DB session
        
    Usage:
        # In an endpoint with Request available:
        db.add(create_audit_log(
            user_id=current_user.id,
            user_email=current_user.email,
            action="create_user",
            resource_type="user",
            details={"email": data.email},
            request=request,
        ))
        
        # In a Celery task (no Request):
        db.add(create_audit_log(
            user_id=triggered_by_user_id,
            action="notification_dispatched",
            resource_type="notification",
            resource_id=notification_id,
            ip_address=triggered_by_ip,
            user_agent="celery-worker",
        ))
    """
    # Extract from Request if provided
    resolved_ip = ip_address
    resolved_ua = user_agent
    
    if request is not None:
        if resolved_ip is None:
            resolved_ip = request.client.host if request.client else None
        if resolved_ua is None:
            resolved_ua = request.headers.get("user-agent")
    
    return AuditLog(
        user_id=user_id,
        user_email=user_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=resolved_ip,
        user_agent=resolved_ua,
    )

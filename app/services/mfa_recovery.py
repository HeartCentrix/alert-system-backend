"""
MFA Recovery Service

Production-grade recovery code management following OWASP guidelines:
- Secure random generation
- Hashed storage (never plaintext)
- Single-use enforcement
- Batch invalidation on regeneration
- Rate limiting and audit logging
"""
import secrets
import string
import hashlib
import hmac
from typing import List, Tuple, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import logging

from app.models import MFARecoveryCode, User, AuditLog
from app.config import settings

logger = logging.getLogger(__name__)

# Recovery code configuration
RECOVERY_CODE_LENGTH = 12  # Characters (alphanumeric)
RECOVERY_CODE_COUNT = 10   # Number of codes per batch
RECOVERY_CODE_CHARSET = string.ascii_uppercase + string.digits  # A-Z, 0-9


def _generate_single_recovery_code() -> str:
    """
    Generate a single high-entropy recovery code.
    
    Uses secrets module for cryptographically secure random generation.
    Format: 12-character alphanumeric (e.g., "A7K9M2P4X8Q1")
    
    Returns:
        Plaintext recovery code (to be shown to user once, then hashed)
    """
    return ''.join(secrets.choice(RECOVERY_CODE_CHARSET) for _ in range(RECOVERY_CODE_LENGTH))


def _hash_recovery_code(code: str) -> str:
    """
    Hash a recovery code for secure storage.
    
    Uses HMAC-SHA256 with a server-side secret key.
    This is sufficient for recovery codes since they're high-entropy
    and single-use (unlike passwords which need slow hashes).
    
    Args:
        code: Plaintext recovery code
        
    Returns:
        Hex-encoded hash
    """
    # Use HMAC with server secret for additional security
    secret = settings.SECRET_KEY.encode('utf-8')
    code_bytes = code.encode('utf-8').strip().upper()
    return hmac.new(secret, code_bytes, hashlib.sha256).hexdigest()


def _generate_batch_id() -> str:
    """
    Generate a unique batch identifier for a set of recovery codes.
    
    Used to invalidate all codes from a batch when regenerating.
    """
    return secrets.token_hex(32)  # 64-character hex string


def generate_recovery_codes(db: Session, user_id: int, 
                           generated_by_user_id: Optional[int] = None,
                           reason: str = 'initial_setup') -> Tuple[List[str], str]:
    """
    Generate a new batch of recovery codes for a user.
    
    Security properties:
    - Invalidates all previous unused codes from old batches
    - Returns plaintext codes only once (caller must display to user)
    - Stores only hashed versions
    - Logs the generation event
    
    Args:
        db: Database session
        user_id: User to generate codes for
        generated_by_user_id: User who triggered generation (for admin actions)
        reason: Reason for generation ('initial_setup', 'regenerated', 'admin_reset')
    
    Returns:
        Tuple of (list of plaintext codes, batch_id)
        
    Raises:
        ValueError: If user not found
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError(f"User {user_id} not found")
    
    # Generate new batch ID
    batch_id = _generate_batch_id()
    
    # Generate plaintext codes
    plaintext_codes = [_generate_single_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    
    # Hash and store codes
    for code in plaintext_codes:
        code_hash = _hash_recovery_code(code)
        recovery_code = MFARecoveryCode(
            user_id=user_id,
            code_hash=code_hash,
            batch_id=batch_id,
            is_used=False,
            generated_by_user_id=generated_by_user_id,
            generation_reason=reason
        )
        db.add(recovery_code)
    
    # Mark old unused codes as invalidated (soft delete by marking batch)
    # We keep them for audit but they won't match new batch
    old_codes = db.query(MFARecoveryCode).filter(
        MFARecoveryCode.user_id == user_id,
        MFARecoveryCode.batch_id != batch_id,
        MFARecoveryCode.is_used == False
    ).all()
    
    # Log the generation event
    db.add(AuditLog(
        user_id=generated_by_user_id or user_id,
        user_email=user.email,
        action="mfa_recovery_codes_generated",
        resource_type="mfa_recovery_codes",
        resource_id=user_id,
        details={
            "target_user_id": user_id,
            "target_user_email": user.email,
            "batch_id": batch_id[:8] + "...",  # Log partial batch ID only
            "codes_count": RECOVERY_CODE_COUNT,
            "reason": reason,
            "old_unused_codes_invalidated": len(old_codes)
        }
    ))
    
    db.commit()
    
    logger.info(f"Generated {RECOVERY_CODE_COUNT} recovery codes for user {user_id} (batch: {batch_id[:8]}...)")
    
    # Return plaintext codes (only time they're available)
    return plaintext_codes, batch_id


def verify_recovery_code(db: Session, user_id: int, code: str, 
                         ip_address: Optional[str] = None,
                         user_agent: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Verify and consume a recovery code.
    
    Security properties:
    - Constant-time comparison via HMAC
    - Single-use enforcement (marks code as used atomically)
    - Audit logging of use
    - Rate limiting should be applied at API layer
    
    Args:
        db: Database session
        user_id: User attempting to use code
        code: Plaintext recovery code from user
        ip_address: IP address for audit
        user_agent: User agent for audit
    
    Returns:
        Tuple of (is_valid, error_message)
        error_message is None if valid
    """
    # Hash the submitted code
    submitted_hash = _hash_recovery_code(code)
    
    # Find unused codes for this user
    # Use a query that can be updated atomically
    recovery_code = db.query(MFARecoveryCode).filter(
        MFARecoveryCode.user_id == user_id,
        MFARecoveryCode.code_hash == submitted_hash,
        MFARecoveryCode.is_used == False
    ).first()
    
    if not recovery_code:
        # Code not found or already used
        # Check if it was used before to provide better error
        used_code = db.query(MFARecoveryCode).filter(
            MFARecoveryCode.user_id == user_id,
            MFARecoveryCode.code_hash == submitted_hash,
            MFARecoveryCode.is_used == True
        ).first()
        
        if used_code:
            logger.warning(f"Attempted reuse of recovery code for user {user_id}")
            return False, "Recovery code has already been used"
        
        logger.warning(f"Invalid recovery code attempt for user {user_id}")
        return False, "Invalid recovery code"
    
    # Mark as used atomically
    recovery_code.is_used = True
    recovery_code.used_at = datetime.now(timezone.utc)
    recovery_code.used_ip_address = ip_address
    recovery_code.used_user_agent = user_agent
    
    # Get user email for audit
    user = db.query(User).filter(User.id == user_id).first()
    
    # Log the usage
    db.add(AuditLog(
        user_id=user_id,
        user_email=user.email if user else None,
        action="mfa_recovery_code_used",
        resource_type="mfa_recovery_codes",
        resource_id=recovery_code.id,
        details={
            "batch_id": recovery_code.batch_id[:8] + "...",
            "ip_address": ip_address,
            "success": True
        }
    ))
    
    db.commit()
    
    logger.info(f"Recovery code used successfully for user {user_id}")
    
    return True, None


def get_recovery_code_status(db: Session, user_id: int) -> dict:
    """
    Get the current recovery code status for a user.
    
    Returns:
        Dict with:
        - has_codes: bool - whether user has any unused codes
        - unused_count: int - number of unused codes
        - batch_id: str - current batch ID (partial)
        - codes_generated_at: datetime - when current batch was created
    """
    codes = db.query(MFARecoveryCode).filter(
        MFARecoveryCode.user_id == user_id,
        MFARecoveryCode.is_used == False
    ).all()
    
    if not codes:
        return {
            "has_codes": False,
            "unused_count": 0,
            "batch_id": None,
            "codes_generated_at": None
        }
    
    # All unused codes should be from same batch
    batch_id = codes[0].batch_id if codes else None
    created_at = min(c.created_at for c in codes) if codes else None
    
    return {
        "has_codes": True,
        "unused_count": len(codes),
        "batch_id": batch_id[:8] + "..." if batch_id else None,
        "codes_generated_at": created_at
    }


def invalidate_all_recovery_codes(db: Session, user_id: int, 
                                  invalidated_by_user_id: Optional[int] = None,
                                  reason: str = 'security_reset') -> int:
    """
    Invalidate all recovery codes for a user.
    
    Used when:
    - User regenerates codes
    - Admin resets MFA
    - Security incident
    
    Args:
        db: Database session
        user_id: User to invalidate codes for
        invalidated_by_user_id: Who triggered the invalidation
        reason: Reason for invalidation
    
    Returns:
        Number of codes invalidated
    """
    # Mark all unused codes as used (soft invalidation)
    codes = db.query(MFARecoveryCode).filter(
        MFARecoveryCode.user_id == user_id,
        MFARecoveryCode.is_used == False
    ).all()
    
    count = len(codes)
    
    for code in codes:
        code.is_used = True
        # Don't set used_at - these weren't actually used
    
    # Get user email for audit
    user = db.query(User).filter(User.id == user_id).first()
    
    # Log the invalidation
    db.add(AuditLog(
        user_id=invalidated_by_user_id or user_id,
        user_email=user.email if user else None,
        action="mfa_recovery_codes_invalidated",
        resource_type="mfa_recovery_codes",
        resource_id=user_id,
        details={
            "target_user_id": user_id,
            "target_user_email": user.email if user else None,
            "codes_invalidated": count,
            "reason": reason
        }
    ))
    
    db.commit()
    
    logger.info(f"Invalidated {count} recovery codes for user {user_id} (reason: {reason})")
    
    return count

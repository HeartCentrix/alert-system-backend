"""
MFA Lifecycle Service

Production-grade MFA management following OWASP and NIST guidelines:
- Secure enrollment flow with reauthentication
- Factor lifecycle management (enroll, disable, reset, replace)
- Recovery code management
- Audit logging and user notifications
- Policy enforcement for privileged users
"""
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session

from app.models import User, MFARecoveryCode, AuditLog
from app.core.security import (
    verify_password,
    verify_totp_code,
    generate_mfa_secret,
    generate_mfa_qr_code_uri,
    user_requires_mfa,
    can_user_self_disable_mfa,
    can_user_reset_mfa,
    get_mfa_policy_info,
    get_recovery_code_regeneration_policy,
    encrypt_mfa_secret,
    is_totp_replay,
)
from app.services.mfa_recovery import (
    generate_recovery_codes,
    verify_recovery_code,
    get_recovery_code_status,
    invalidate_all_recovery_codes,
)

# ─── ERROR MESSAGE CONSTANTS ──────────────────────────────────────────────────
TOTP_REPLAY_MSG = "This TOTP code was already used. Please enter a fresh code from your authenticator app."
INVALID_CURRENT_PASSWORD_MSG = "The current password you entered is incorrect."


logger = logging.getLogger(__name__)

# Reauthentication token TTL (5 minutes)
REAUTH_TOKEN_TTL_SECONDS = 300


class MFAService:
    """
    Service for managing MFA lifecycle operations.

    All operations require proper authentication and authorization.
    Sensitive operations require recent reauthentication.
    """

    def __init__(self, db: Session):
        self.db = db

    def get_mfa_status(self, user: User) -> dict:
        """
        Get comprehensive MFA status for a user.

        Returns safe metadata only - never exposes secrets or recovery codes.

        Args:
            user: User model instance

        Returns:
            Dict with MFA status information
        """
        recovery_status = get_recovery_code_status(self.db, user.id)
        policy_info = get_mfa_policy_info(user)

        return {
            "mfa_enabled": user.mfa_enabled,
            "mfa_required": policy_info["mfa_required"],
            "mfa_configured": bool(user.mfa_secret and user.mfa_secret.strip()),
            "has_recovery_codes": recovery_status["has_codes"],
            "recovery_codes_count": recovery_status["unused_count"],
            "can_disable": policy_info["can_self_disable"],
            "pending_enrollment": bool(user.mfa_secret and not user.mfa_enabled),
        }

    def start_enrollment(self, user: User, current_password: str) -> Tuple[str, str, str]:
        """
        Start MFA enrollment for a user.

        Security requirements:
        - Requires current password verification (reauthentication)
        - Generates new pending secret (MFA not enabled yet)
        - Invalidates any previous pending enrollment

        Args:
            user: User model instance
            current_password: User's current password for verification

        Returns:
            Tuple of (secret, qr_code_uri, manual_entry_key)

        Raises:
            ValueError: If password verification fails
        """
        # Verify current password (reauthentication)
        if not verify_password(current_password, user.hashed_password):
            logger.warning(f"Invalid password during MFA enrollment start for user {user.id}")
            raise ValueError(INVALID_CURRENT_PASSWORD_MSG)

        # Generate new secret
        secret = generate_mfa_secret()
        qr_code_uri = generate_mfa_qr_code_uri(user.email, secret)

        # Encrypt and store secret (do NOT enable MFA yet)
        # MFA will be enabled only after OTP verification
        encrypted_secret = encrypt_mfa_secret(secret)
        user.mfa_secret = encrypted_secret
        user.mfa_enabled = False  # Explicitly ensure not enabled

        # Invalidate any existing recovery codes from previous enrollment
        # (in case this is a reset/re-enrollment)
        invalidate_all_recovery_codes(
            db=self.db,
            user_id=user.id,
            invalidated_by_user_id=user.id,
            reason='enrollment_started'
        )

        logger.info(f"MFA enrollment started for user {user.id}")

        return secret, qr_code_uri, secret  # manual_entry_key same as secret

    def complete_enrollment(self, user: User, code: str) -> Tuple[List[str], str]:
        """
        Complete MFA enrollment by verifying OTP code.

        Security requirements:
        - Validates OTP against pending secret
        - Only enables MFA on successful verification
        - Generates recovery codes
        - Audit logged

        Args:
            user: User model instance
            code: 6-digit TOTP code from authenticator app

        Returns:
            Tuple of (recovery_codes_plaintext, batch_id)

        Raises:
            ValueError: If code verification fails or no pending enrollment
        """
        # Check if user has a pending secret
        if not user.mfa_secret:
            logger.warning(f"No pending MFA enrollment for user {user.id}")
            raise ValueError("MFA enrollment not initiated. Please start enrollment first.")

        # Verify the OTP code
        if not verify_totp_code(user.mfa_secret, code):
            logger.warning(f"Invalid OTP code during MFA enrollment for user {user.id}")
            raise ValueError("Invalid verification code. Please try again.")

        # Replay protection — reject reuse within the same 30-second window
        if is_totp_replay(user, code):
            logger.warning(f"TOTP replay attempt detected during MFA enrollment for user {user.id}")
            raise ValueError(TOTP_REPLAY_MSG)

        # Record this code as used
        user.last_used_totp_code = code
        user.last_used_totp_at = datetime.now(timezone.utc)

        # Enable MFA
        user.mfa_enabled = True

        # Generate recovery codes
        plaintext_codes, batch_id = generate_recovery_codes(
            db=self.db,
            user_id=user.id,
            generated_by_user_id=user.id,
            reason='initial_setup'
        )

        # Audit log
        self.db.add(AuditLog(
            user_id=user.id,
            user_email=user.email,
            action="mfa_enabled",
            resource_type="user",
            resource_id=user.id,
            details={
                "method": "totp",
                "recovery_codes_generated": len(plaintext_codes)
            }
        ))

        logger.info(f"MFA enrollment completed for user {user.id}")

        return plaintext_codes, batch_id

    def disable_mfa(self, user: User, current_password: str, mfa_code: str) -> bool:
        """
        Disable MFA for a user.

        Security requirements:
        - Checks if user is allowed to disable (policy)
        - Requires current password verification
        - Requires current MFA code or recovery code verification
        - Clears MFA state and recovery codes
        - Audit logged

        Args:
            user: User model instance
            current_password: User's current password
            mfa_code: Current TOTP code or recovery code

        Returns:
            True if MFA was disabled successfully

        Raises:
            PermissionError: If user is not allowed to disable MFA
            ValueError: If verification fails
        """
        # Check if user can self-disable
        if not can_user_self_disable_mfa(user):
            logger.warning(f"User {user.id} attempted to disable MFA but is not allowed")
            raise PermissionError(
                "MFA cannot be disabled for your account. "
                "Contact an administrator if you need assistance."
            )

        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            logger.warning(f"Invalid password during MFA disable for user {user.id}")
            raise ValueError(INVALID_CURRENT_PASSWORD_MSG)

        # Verify current MFA code or recovery code
        if not self._verify_mfa_or_recovery_code(user, mfa_code):
            logger.warning(f"Invalid MFA code during disable for user {user.id}")
            raise ValueError("Invalid MFA code or recovery code")

        # Disable MFA
        user.mfa_enabled = False
        user.mfa_secret = None

        # Invalidate all recovery codes
        invalidate_all_recovery_codes(
            db=self.db,
            user_id=user.id,
            invalidated_by_user_id=user.id,
            reason='mfa_disabled'
        )

        # Audit log
        self.db.add(AuditLog(
            user_id=user.id,
            user_email=user.email,
            action="mfa_disabled",
            resource_type="user",
            resource_id=user.id,
            details={"method": "self_service"}
        ))

        logger.info(f"MFA disabled for user {user.id}")

        return True

    def start_reset(self, user: User, current_password: str, mfa_code: Optional[str] = None) -> Tuple[str, str, str]:
        """
        Start MFA reset/replacement flow.

        Use this when:
        - User changed devices
        - User lost authenticator but has recovery codes
        - User wants to rotate MFA secrets

        Security requirements:
        - Requires current password verification
        - Requires current MFA code OR recovery code (if available)
        - For locked-out users, mfa_code can be None (admin-assisted path)
        - Invalidates old MFA secret and recovery codes
        - Creates pending new enrollment

        Args:
            user: User model instance
            current_password: User's current password
            mfa_code: Current TOTP code or recovery code (optional for admin reset)

        Returns:
            Tuple of (secret, qr_code_uri, manual_entry_key)

        Raises:
            ValueError: If verification fails
        """
        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            logger.warning(f"Invalid password during MFA reset for user {user.id}")
            raise ValueError(INVALID_CURRENT_PASSWORD_MSG)

        # Verify current MFA code if provided
        # For locked-out users, this may be None (recovery path)
        if mfa_code:
            if not self._verify_mfa_or_recovery_code(user, mfa_code):
                logger.warning(f"Invalid MFA code during reset for user {user.id}")
                raise ValueError("Invalid MFA code or recovery code")

        # Invalidate old MFA secret
        old_secret = user.mfa_secret
        user.mfa_secret = None
        user.mfa_enabled = False

        # Invalidate old recovery codes
        invalidate_all_recovery_codes(
            db=self.db,
            user_id=user.id,
            invalidated_by_user_id=user.id,
            reason='mfa_reset'
        )

        # Generate new secret for re-enrollment
        secret = generate_mfa_secret()
        qr_code_uri = generate_mfa_qr_code_uri(user.email, secret)

        # Encrypt and store new secret (pending enrollment)
        encrypted_secret = encrypt_mfa_secret(secret)
        user.mfa_secret = encrypted_secret

        # Audit log
        self.db.add(AuditLog(
            user_id=user.id,
            user_email=user.email,
            action="mfa_reset_started",
            resource_type="user",
            resource_id=user.id,
            details={
                "old_secret_invalidated": bool(old_secret),
                "reason": "user_initiated_reset"
            }
        ))

        logger.info(f"MFA reset started for user {user.id}")

        return secret, qr_code_uri, secret

    def complete_reset(self, user: User, code: str) -> Tuple[List[str], str]:
        """
        Complete MFA reset by verifying new OTP code.

        Args:
            user: User model instance
            code: 6-digit TOTP code from new authenticator app

        Returns:
            Tuple of (recovery_codes_plaintext, batch_id)

        Raises:
            ValueError: If code verification fails
        """
        # This is essentially the same as complete_enrollment
        # but with different audit logging
        if not user.mfa_secret:
            logger.warning(f"No pending MFA enrollment for user {user.id} during reset")
            raise ValueError("MFA reset not initiated. Please start reset first.")

        if not verify_totp_code(user.mfa_secret, code):
            logger.warning(f"Invalid OTP code during MFA reset for user {user.id}")
            raise ValueError("Invalid verification code. Please try again.")

        # Replay protection — reject reuse within the same 30-second window
        if is_totp_replay(user, code):
            logger.warning(f"TOTP replay attempt detected during MFA reset for user {user.id}")
            raise ValueError(TOTP_REPLAY_MSG)

        # Record this code as used
        user.last_used_totp_code = code
        user.last_used_totp_at = datetime.now(timezone.utc)

        # Enable MFA
        user.mfa_enabled = True

        # Generate new recovery codes
        plaintext_codes, batch_id = generate_recovery_codes(
            db=self.db,
            user_id=user.id,
            generated_by_user_id=user.id,
            reason='mfa_reset'
        )

        # Audit log
        self.db.add(AuditLog(
            user_id=user.id,
            user_email=user.email,
            action="mfa_reset_completed",
            resource_type="user",
            resource_id=user.id,
            details={
                "method": "totp",
                "recovery_codes_generated": len(plaintext_codes)
            }
        ))

        logger.info(f"MFA reset completed for user {user.id}")

        return plaintext_codes, batch_id

    def _verify_totp_for_regeneration(self, user: User, mfa_code: Optional[str]) -> None:
        """Verify TOTP code for recovery code regeneration."""
        if not mfa_code:
            logger.warning(f"Missing TOTP code for user {user.id} during regeneration")
            raise ValueError("TOTP code is required")
        if not verify_totp_code(user.mfa_secret, mfa_code):
            logger.warning(f"Invalid TOTP code during regeneration for user {user.id}")
            raise ValueError("Invalid TOTP code")
        if is_totp_replay(user, mfa_code):
            logger.warning(f"TOTP replay attempt detected during regeneration for user {user.id}")
            raise ValueError(TOTP_REPLAY_MSG)
        user.last_used_totp_code = mfa_code
        user.last_used_totp_at = datetime.now(timezone.utc)

    def _verify_recovery_code_for_regeneration(
        self, user: User, recovery_code: Optional[str],
        policy: dict, ip_address: Optional[str], user_agent: Optional[str]
    ) -> None:
        """Verify recovery code fallback for recovery code regeneration."""
        if not policy["allows_recovery_code_fallback"]:
            logger.warning(f"Privileged user {user.id} attempted recovery code fallback - denied")
            raise PermissionError(
                "Recovery code fallback is not allowed for privileged accounts. "
                "Please use your authenticator app or contact an administrator."
            )
        if not recovery_code:
            logger.warning(f"Missing recovery code for user {user.id} during regeneration")
            raise ValueError("Recovery code is required")
        is_valid, error = verify_recovery_code(
            db=self.db, user_id=user.id, code=recovery_code,
            ip_address=ip_address, user_agent=user_agent
        )
        if not is_valid:
            logger.warning(f"Invalid recovery code during regeneration for user {user.id}: {error}")
            raise ValueError(error or "Invalid recovery code")

    def _verify_mfa_proof_for_regeneration(
        self, user: User, method: str, mfa_code: Optional[str],
        recovery_code: Optional[str], policy: dict,
        ip_address: Optional[str], user_agent: Optional[str]
    ) -> None:
        """Verify MFA proof (TOTP or recovery code) for recovery code regeneration."""
        if method == "totp":
            self._verify_totp_for_regeneration(user, mfa_code)
        elif method == "recovery_code":
            self._verify_recovery_code_for_regeneration(
                user, recovery_code, policy, ip_address, user_agent
            )
        else:
            logger.warning(f"Invalid method for user {user.id} during regeneration: {method}")
            raise ValueError(f"Invalid verification method: {method}")

    def regenerate_recovery_codes(
        self,
        user: User,
        current_password: str,
        method: str = "totp",
        mfa_code: Optional[str] = None,
        recovery_code: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[List[str], str, int]:
        """
        Regenerate recovery codes for a user with dual-proof verification.

        Security requirements (OWASP/NIST):
        - Requires password verification (knowledge factor)
        - Requires MFA proof (possession factor):
          - TOTP code from authenticator app, OR
          - Single unused recovery code (normal users only, when authenticator unavailable)
        - Privileged users cannot use recovery code fallback
        - Invalidates all previous unused codes atomically
        - Returns new plaintext codes (only time available)
        - Audit logged with full details

        Args:
            user: User model instance
            current_password: User's current password
            method: Verification method - "totp" or "recovery_code"
            mfa_code: TOTP code (6 digits) - required if method="totp"
            recovery_code: Recovery code - required if method="recovery_code"
            ip_address: IP address for audit
            user_agent: User agent for audit

        Returns:
            Tuple of (recovery_codes_plaintext, batch_id, old_codes_invalidated_count)

        Raises:
            ValueError: If password or MFA verification fails
            PermissionError: If user is not allowed to use requested method
        """
        # Get regeneration policy for this user
        policy = get_recovery_code_regeneration_policy(user)

        # Validate that MFA proof is required for MFA-enabled users
        if policy["requires_mfa_proof"] and not user.mfa_enabled:
            logger.warning(f"User {user.id} attempted regeneration without MFA enabled")
            raise ValueError("MFA must be enabled to regenerate recovery codes")

        # For users without MFA, regeneration is not applicable
        if not user.mfa_enabled:
            logger.warning(f"User {user.id} without MFA attempted recovery code regeneration")
            raise ValueError("MFA must be enabled to regenerate recovery codes")

        # STEP 1: Verify password (knowledge factor)
        if not verify_password(current_password, user.hashed_password):
            logger.warning(f"Invalid password during recovery code regeneration for user {user.id}")
            raise ValueError(INVALID_CURRENT_PASSWORD_MSG)

        # STEP 2: Verify MFA proof (possession factor)
        if policy["requires_mfa_proof"]:
            self._verify_mfa_proof_for_regeneration(
                user=user,
                method=method,
                mfa_code=mfa_code,
                recovery_code=recovery_code,
                policy=policy,
                ip_address=ip_address,
                user_agent=user_agent
            )

        # STEP 3: Count old codes before invalidation (for audit and response)
        old_codes = self.db.query(MFARecoveryCode).filter(
            MFARecoveryCode.user_id == user.id,
            MFARecoveryCode.is_used == False
        ).all()
        old_codes_count = len(old_codes)

        # STEP 4: Invalidate old codes atomically
        invalidate_all_recovery_codes(
            db=self.db,
            user_id=user.id,
            invalidated_by_user_id=user.id,
            reason='user_regenerated'
        )

        # STEP 5: Generate new codes
        plaintext_codes, batch_id = generate_recovery_codes(
            db=self.db,
            user_id=user.id,
            generated_by_user_id=user.id,
            reason='regenerated'
        )

        # STEP 6: Audit log with full details
        self.db.add(AuditLog(
            user_id=user.id,
            user_email=user.email,
            action="mfa_recovery_codes_regenerated",
            resource_type="mfa_recovery_codes",
            resource_id=user.id,
            details={
                "codes_generated": len(plaintext_codes),
                "old_codes_invalidated": old_codes_count,
                "method": method,
                "ip_address": ip_address,
                "success": True
            }
        ))

        logger.info(
            f"Recovery codes regenerated for user {user.id} "
            f"(method: {method}, old codes invalidated: {old_codes_count})"
        )

        return plaintext_codes, batch_id, old_codes_count

    def _verify_mfa_or_recovery_code(self, user: User, code: str) -> bool:
        """
        Verify either a TOTP code or a recovery code.

        Args:
            user: User model instance
            code: TOTP code (6 digits) or recovery code (alphanumeric)

        Returns:
            True if code is valid
        """
        # Try TOTP verification first (6 digits)
        if code.strip().isdigit() and len(code.strip()) == 6:
            if user.mfa_secret:
                return verify_totp_code(user.mfa_secret, code)
            return False

        # Try recovery code verification
        is_valid, _ = verify_recovery_code(
            db=self.db,
            user_id=user.id,
            code=code
        )
        return is_valid


def get_mfa_service(db: Session) -> MFAService:
    """Factory function to get MFA service instance."""
    return MFAService(db)

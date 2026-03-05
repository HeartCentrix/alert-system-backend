import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, RefreshToken, AuditLog, UserRole
from app.schemas import (
    LoginRequest, TokenResponse, RefreshRequest, UserResponse,
    PasswordResetRequest, PasswordResetConfirm, ChangePasswordRequest
)
from app.core.security import (
    verify_password, hash_password, create_access_token,
    create_refresh_token, decode_token
)
from app.core.deps import get_current_user
from app.services.messaging import email_service
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.email == request.email,
        User.deleted_at == None
    ).first()

    # Check if user exists
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No account found with this email address"
        )

    # Check if account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact your administrator."
        )

    # Check password
    if not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token_str = create_refresh_token({"sub": str(user.id)})

    # Save refresh token
    rt = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(rt)

    # Update last login
    user.last_login = datetime.now(timezone.utc)

    # Audit log
    db.add(AuditLog(
        user_id=user.id,
        action="login",
        resource_type="user",
        resource_id=user.id,
        ip_address=req.client.host if req.client else None
    ))
    db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        user=UserResponse.model_validate(user)
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(request: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_token(request.refresh_token)

    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Check token in DB
    rt = db.query(RefreshToken).filter(
        RefreshToken.token == request.refresh_token,
        RefreshToken.revoked == False
    ).first()

    if not rt or rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # Check if user exists, is active, AND is not soft-deleted
    user = db.query(User).filter(
        User.id == rt.user_id,
        User.is_active == True,
        User.deleted_at == None
    ).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Revoke old token, issue new ones
    rt.revoked = True
    new_access = create_access_token({"sub": str(user.id), "role": user.role})
    new_refresh_str = create_refresh_token({"sub": str(user.id)})

    new_rt = RefreshToken(
        user_id=user.id,
        token=new_refresh_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(new_rt)
    db.commit()

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh_str,
        user=UserResponse.model_validate(user)
    )


@router.post("/logout")
def logout(
    request: RefreshRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rt = db.query(RefreshToken).filter(
        RefreshToken.token == request.refresh_token,
        RefreshToken.user_id == current_user.id
    ).first()
    if rt:
        rt.revoked = True
        db.commit()
    return {"message": "Logged out successfully"}


@router.post("/forgot-password")
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email, User.deleted_at == None).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email address"
        )
    
    token = secrets.token_urlsafe(32)
    user.password_reset_token = token
    user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
    db.commit()
    email_service.send_password_reset_email(user.email, token, user.full_name)
    
    return {"message": "Password reset email sent successfully"}


@router.post("/reset-password")
def reset_password(request: PasswordResetConfirm, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.password_reset_token == request.token,
        User.password_reset_expires > datetime.now(timezone.utc),
        User.deleted_at == None
    ).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    user.hashed_password = hash_password(request.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    db.commit()
    return {"message": "Password reset successfully"}


@router.post("/change-password")
def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(request.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    current_user.hashed_password = hash_password(request.new_password)
    db.commit()
    return {"message": "Password changed successfully"}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, UserRole
from app.core.security import verify_password

security = HTTPBasic()


def get_super_admin_user(
    credentials: HTTPBasicCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    HTTP Basic Auth for super admin access to docs.
    Browser shows native login popup.
    """
    user = db.query(User).filter(User.email == credentials.username).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required",
        )

    if not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return user


router = APIRouter()


@router.get("/docs", include_in_schema=False)
async def swagger_docs(current_user: User = Depends(get_super_admin_user)):
    """Protected Swagger UI — requires super admin HTTP Basic Auth."""
    return get_swagger_ui_html(
        openapi_url="/api/v1/openapi.json",
        title="TM Alert API - Swagger UI",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


@router.get("/redoc", include_in_schema=False)
async def redoc_docs(current_user: User = Depends(get_super_admin_user)):
    """Protected ReDoc — requires super admin HTTP Basic Auth."""
    return get_redoc_html(
        openapi_url="/api/v1/openapi.json",
        title="TM Alert API - ReDoc",
        redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


@router.get("/openapi.json", include_in_schema=False)
async def openapi(current_user: User = Depends(get_super_admin_user)):
    """Protected OpenAPI schema — requires super admin HTTP Basic Auth."""
    from app.main import app
    return get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
        servers=app.servers,
    )

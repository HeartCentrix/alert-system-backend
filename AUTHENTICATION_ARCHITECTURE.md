# TM Alert Backend Authentication & Session Management

## Complete Situation Analysis (March 2026)

---

## 📋 Current Situation

### Deployment Architecture

```
┌─────────────────────────────────────┐
│  Frontend: Vercel                   │
│  URL: https://alert-system-frontend-jq7u.vercel.app
│  Framework: React + Vite            │
└─────────────────────────────────────┘
              ↓ (HTTPS, Cross-Origin)
┌─────────────────────────────────────┐
│  Backend: Railway                   │
│  URL: https://web-production-*.up.railway.app
│  Framework: FastAPI + SQLAlchemy    │
└─────────────────────────────────────┘
```

### The Problem

**Cross-Origin Cookie Restrictions:**

| Step | What Happens | Why It Fails |
|------|--------------|--------------|
| 1 | Backend sets cookie: `Domain=.up.railway.app` | Browser security policy |
| 2 | Request comes from `vercel.app` | Different root domain |
| 3 | Browser blocks cookie | `railway.app ≠ vercel.app` |
| 4 | Page reload (F5) | No refresh token available |
| 5 | User logged out | Session cannot be restored |

**Browser Console Error:**
```
Cookie domain must match response origin
```

### Why Traditional Cookies Fail

```python
# ❌ This doesn't work for cross-origin:
response.set_cookie(
    key="refresh_token",
    value=token,
    domain=".up.railway.app",  # ← Browser rejects this!
    httponly=True,
    secure=True,
    samesite="none"
)

# Error: "Cookie domain must match response origin"
# Reason: Response from railway.app cannot set cookie for vercel.app
```

---

## 🎯 Original Design (How It Was Supposed to Work)

### Intended Architecture (Same-Origin)

```
┌──────────────────────────────────────────────┐
│  Single Domain: app.tmalert.com              │
│                                               │
│  ┌─────────────┐    ┌──────────────┐         │
│  │  Frontend   │    │   Backend    │         │
│  │  (static)   │───→│   (API)      │         │
│  │  /          │    │   /api/v1/   │         │
│  └─────────────┘    └──────────────┘         │
│         ↑                  ↑                  │
│         └──────────────────┘                  │
│         Same origin = Cookies work!           │
└──────────────────────────────────────────────┘
```

### Original Cookie Configuration

**File:** `app/api/auth.py`

```python
def _set_refresh_cookie(response: Response, token: str, expire_days: int) -> None:
    """
    Attach the refresh token as an HttpOnly cookie.
    
    Security properties:
    - HttpOnly: JS cannot read it — eliminates XSS token theft
    - Secure: HTTPS only — never sent over plain HTTP
    - SameSite=Strict: CSRF protection
    - Path=/api/v1/auth: cookie only sent to auth endpoints
    """
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",  # Maximum CSRF protection
        path="/api/v1/auth",
        max_age=expire_days * 86400,  # 7 days
    )
```

### Original Login Flow

**File:** `app/api/auth.py`

```python
@router.post("/login")
async def login(request: LoginRequest, response: Response, db: Session):
    # ... authentication logic ...
    
    # Create tokens
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token_str = create_refresh_token({"sub": str(user.id)})
    
    # Save refresh token to database
    rt = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )
    db.add(rt)
    db.commit()
    
    # Set refresh token as HttpOnly cookie
    _set_refresh_cookie(response, refresh_token_str, 7)
    
    # Return ONLY access token in body
    return LoginSuccessResponse(
        status="success",
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
        # ❌ NO refresh_token in body (security risk)
    )
```

### Original Refresh Flow

**File:** `app/api/auth.py`

```python
@router.post("/refresh", response_model=TokenResponse)
def refresh_token(req: Request, response: Response, db: Session):
    """
    Refresh access token using the refresh token from HttpOnly cookie.
    """
    # Read refresh token from HttpOnly cookie ONLY
    refresh_token_str = req.cookies.get("refresh_token")
    
    if not refresh_token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token"
        )
    
    # ... validate token ...
    
    # Revoke old token, issue new ones
    rt.revoked = True
    new_access = create_access_token({"sub": str(user.id), "role": user.role})
    new_refresh_str = create_refresh_token({"sub": str(user.id)})
    
    # Set new refresh token as HttpOnly cookie
    _set_refresh_cookie(response, new_refresh_str, 7)
    
    return TokenResponse(
        access_token=new_access,
        token_type="bearer",
        user=UserResponse.model_validate(user)
        # ❌ NO refresh_token in body
    )
```

---

## 🔧 Current Workaround (Cross-Origin Solution)

### Temporary Solution (Dual Delivery)

```
┌─────────────────────────────────────┐
│  Backend Response                   │
│  ┌───────────────────────────────┐  │
│  │ Response Body                 │  │
│  │ - access_token: "..."         │  │
│  │ - refresh_token: "..." ← NEW  │  │ For cross-origin (Vercel)
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │ Set-Cookie Header             │  │
│  │ - refresh_token=...           │  │ For same-origin (Railway)
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### Implementation

#### Schema Changes

**File:** `app/schemas.py`

```python
class TokenResponse(BaseModel):
    """Response model for token operations."""
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"
    refresh_token: Optional[str] = None  # ← NEW: For cross-origin deployments (Vercel + Railway)


class LoginSuccessResponse(BaseModel):
    """Standard login success response with tokens."""
    status: str = "success"
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"
    refresh_token: Optional[str] = None  # ← NEW: For cross-origin deployments (Vercel + Railway)
    recovery_codes: Optional[List[str]] = None  # Only present on first MFA setup
    recovery_codes_warning: Optional[str] = None  # Security warning
```

#### Login Endpoint Changes

**File:** `app/api/auth.py`

```python
@router.post("/login")
async def login(request: LoginRequest, response: Response, db: Session):
    # ... authentication logic ...
    
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token_str = create_refresh_token({"sub": str(user.id)})
    
    # Save refresh token
    rt = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(rt)
    db.commit()
    
    # Set refresh token as HttpOnly cookie (for same-origin fallback)
    _set_refresh_cookie(response, refresh_token_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    return LoginSuccessResponse(
        status="success",
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        refresh_token=refresh_token_str  # ← NEW: For cross-origin deployments (Vercel + Railway)
    )
```

#### Refresh Endpoint Changes

**File:** `app/api/auth.py`

```python
@router.post("/refresh", response_model=TokenResponse)
def refresh_token(req: Request, response: Response, db: Session = Depends(get_db)):
    """
    Refresh access token using the refresh token from HttpOnly cookie or request body.

    Security:
    - Refresh token read from HttpOnly cookie (primary) or request body (fallback for cross-origin)
    - Old token revoked, new token issued (rotation)
    - New refresh token set as HttpOnly cookie
    """
    # Try to read refresh token from HttpOnly cookie first (same-origin fallback)
    refresh_token_str = req.cookies.get("refresh_token")
    
    # If no cookie, try request body (cross-origin fallback for Vercel + Railway)
    if not refresh_token_str:
        try:
            import json
            content_type = req.headers.get("content-type", "")
            if "application/json" in content_type:
                import asyncio
                body_bytes = asyncio.run(req.body())
                body_data = json.loads(body_bytes.decode())
                refresh_token_str = body_data.get("refresh_token")
        except Exception:
            pass  # Will raise 401 below if no token found
    
    if not refresh_token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token"
        )
    
    # ... validate token ...
    
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
    
    # Set new refresh token as HttpOnly cookie
    _set_refresh_cookie(response, new_refresh_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    return TokenResponse(
        access_token=new_access,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        refresh_token=new_refresh_str  # ← NEW: For cross-origin deployments (Vercel + Railway)
    )
```

#### MFA Verify Login Changes

**File:** `app/api/auth.py`

```python
@router.post("/mfa/verify-login", response_model=LoginSuccessResponse)
async def verify_mfa_and_complete_login(
    request: MFAVerifyLoginRequest,
    req: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    # ... MFA verification logic ...
    
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token_str = create_refresh_token({"sub": str(user.id)})
    
    # Save refresh token
    rt = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(rt)
    db.commit()
    
    # Set refresh token as HttpOnly cookie
    _set_refresh_cookie(response, refresh_token_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Build response with recovery codes if this was first MFA setup
    # Include refresh_token in body for cross-origin deployments (Vercel + Railway)
    response_data = {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
        "refresh_token": refresh_token_str,  # ← NEW: For cross-origin deployments
    }
    
    if was_new_mfa and recovery_codes:
        response_data["recovery_codes"] = recovery_codes
        response_data["recovery_codes_warning"] = "Store these codes securely. They will not be shown again."
    
    return LoginSuccessResponse(**response_data)
```

#### Recovery Code Verify Changes

**File:** `app/api/auth.py`

```python
@router.post("/mfa/recovery-code/verify", response_model=LoginSuccessResponse)
async def verify_recovery_code_and_login(
    request: MFARecoveryCodeVerifyRequest,
    req: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    # ... recovery code verification logic ...
    
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token_str = create_refresh_token({"sub": str(user.id)})
    
    rt = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(rt)
    db.commit()
    
    # Set refresh token as HttpOnly cookie (for same-origin fallback)
    _set_refresh_cookie(response, refresh_token_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    return LoginSuccessResponse(
        status="success",
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        refresh_token=refresh_token_str  # ← NEW: For cross-origin deployments (Vercel + Railway)
    )
```

### Cookie Configuration (Current)

**File:** `app/api/auth.py`

```python
def _set_refresh_cookie(response: Response, token: str, expire_days: int) -> None:
    """
    Attach the refresh token as an HttpOnly cookie on a FastAPI Response object.
    
    NOTE: For cross-origin deployments (Vercel + Railway), cookies are set but
    browsers may block them. Frontend should also accept refresh_token in response body.

    Security properties:
    - HttpOnly: JS cannot read it — eliminates XSS token theft
    - Secure: HTTPS only — never sent over plain HTTP
    - SameSite=None: Required for cross-origin cookie usage
    - Path=/api/v1/auth: cookie only sent to auth endpoints

    In development mode, secure=False so localhost works without HTTPS.
    """
    is_secure = settings.APP_ENV != "development"
    
    # For cross-origin (Vercel -> Railway), we need SameSite=None
    # This is secure because we always use Secure flag (HTTPS only)
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,
        secure=is_secure,
        samesite="none",  # Required for cross-origin (Vercel to Railway)
        path="/api/v1/auth",  # Scoped: only sent to auth endpoints
        max_age=expire_days * 86400,  # seconds
    )
```

### Security Trade-offs

| Aspect | Original (HttpOnly) | Current (Dual Delivery) |
|--------|---------------------|-------------------------|
| **XSS Protection** | ✅ Full (token inaccessible) | ⚠️ Partial (token in body) |
| **CSRF Protection** | ✅ Full (SameSite=Strict) | ⚠️ Partial (SameSite=None) |
| **Cross-Origin** | ❌ Doesn't work | ✅ Works |
| **Same-Origin** | ✅ Works | ✅ Works (cookie fallback) |
| **OWASP Compliance** | ✅ Full | ⚠️ Acceptable for temporary |

### Why This is Acceptable (Temporary)

1. ✅ **Dual delivery** - Cookie still set for same-origin users
2. ✅ **HTTPS only** - Secure flag always set in production
3. ✅ **Token rotation** - Refresh tokens rotated on each use
4. ✅ **Database tracking** - All refresh tokens tracked and revocable
5. ✅ **CSRF tokens** - X-CSRF-Token header still required
6. ✅ **Short-lived** - Access token: 1 hour, Refresh token: 7 days
7. ✅ **Audit logging** - All auth events logged

---

## 🚀 Future State (With Custom Domain)

### Target Architecture

```
┌──────────────────────────────────────────────┐
│  Custom Domain: tmalert.com                  │
│                                               │
│  ┌─────────────────┐    ┌─────────────────┐  │
│  │ Frontend        │    │ Backend         │  │
│  │ app.tmalert.com │    │ api.tmalert.com │  │
│  │ (Vercel)        │    │ (Railway/AWS)   │  │
│  └─────────────────┘    └─────────────────┘  │
│         ↑                        ↑           │
│         └────────────────────────┘           │
│         Cookie Domain: .tmalert.com          │
│         (Works across ALL subdomains!)       │
└──────────────────────────────────────────────┘
```

### DNS Configuration

```
tmalert.com (root)
├── app.tmalert.com     → Vercel (CNAME)
├── api.tmalert.com     → Railway/AWS (CNAME)
└── www.tmalert.com     → Redirect to app.tmalert.com
```

### Cookie Configuration (Future)

**File:** `app/api/auth.py`

```python
def _set_refresh_cookie(response: Response, token: str, expire_days: int) -> None:
    """
    Attach the refresh token as an HttpOnly cookie.
    
    With custom domain, cookies work across subdomains:
    - api.tmalert.com can set cookie for .tmalert.com
    - app.tmalert.com can read that cookie
    
    Security properties:
    - HttpOnly: JS cannot read it — eliminates XSS token theft
    - Secure: HTTPS only — never sent over plain HTTP
    - SameSite=Lax: CSRF protection while allowing cross-subdomain
    - Domain=.tmalert.com: Works across all subdomains
    - Path=/api/v1/auth: cookie only sent to auth endpoints
    """
    is_secure = settings.APP_ENV != "development"
    
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,
        secure=is_secure,
        samesite="lax",  # Can use lax with custom domain
        domain=".tmalert.com",  # ← Works across ALL subdomains!
        path="/api/v1/auth",
        max_age=expire_days * 86400,
    )
```

### Login Endpoint (Future - Revert)

**File:** `app/api/auth.py`

```python
@router.post("/login")
async def login(request: LoginRequest, response: Response, db: Session):
    # ... authentication logic ...
    
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token_str = create_refresh_token({"sub": str(user.id)})
    
    # Save refresh token
    rt = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(rt)
    db.commit()
    
    # Set refresh token as HttpOnly cookie
    _set_refresh_cookie(response, refresh_token_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Return ONLY access token in body (REVERT to original)
    return LoginSuccessResponse(
        status="success",
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
        # ❌ NO refresh_token in body (security - back to original)
    )
```

### Refresh Endpoint (Future - Revert)

**File:** `app/api/auth.py`

```python
@router.post("/refresh", response_model=TokenResponse)
def refresh_token(req: Request, response: Response, db: Session = Depends(get_db)):
    """
    Refresh access token using the refresh token from HttpOnly cookie.

    Security:
    - Refresh token read from HttpOnly cookie ONLY
    - Old token revoked, new token issued (rotation)
    - New refresh token set as HttpOnly cookie
    """
    # Read refresh token from HttpOnly cookie ONLY (REVERT to original)
    refresh_token_str = req.cookies.get("refresh_token")
    
    if not refresh_token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token"
        )
    
    # ... validate token ...
    
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
    
    # Set new refresh token as HttpOnly cookie
    _set_refresh_cookie(response, new_refresh_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Return ONLY access token in body (REVERT to original)
    return TokenResponse(
        access_token=new_access,
        token_type="bearer",
        user=UserResponse.model_validate(user)
        # ❌ NO refresh_token in body
    )
```

### Schema Changes (Future - Revert)

**File:** `app/schemas.py`

```python
class TokenResponse(BaseModel):
    """Response model for token operations."""
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"
    # refresh_token: Optional[str] = None  ← REMOVE THIS (security)


class LoginSuccessResponse(BaseModel):
    """Standard login success response with tokens."""
    status: str = "success"
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"
    # refresh_token: Optional[str] = None  ← REMOVE THIS (security)
    recovery_codes: Optional[List[str]] = None
    recovery_codes_warning: Optional[str] = None
```

### Security Improvements (Custom Domain)

| Aspect | Current (Dual Delivery) | Future (HttpOnly Cookie) |
|--------|-------------------------|--------------------------|
| **XSS Protection** | ⚠️ Partial | ✅ Full |
| **CSRF Protection** | ⚠️ Partial | ✅ Full |
| **Cross-Subdomain** | ✅ Works | ✅ Works |
| **Compliance** | ⚠️ Acceptable | ✅ OWASP Compliant |
| **Code Complexity** | ⚠️ Higher (dual logic) | ✅ Lower (cookie-only) |
| **Token Exposure** | ⚠️ In response body | ✅ Never exposed to JS |

---

## ☁️ Future Migration (AWS/Cloud Shift)

### Scenario: Moving Backend from Railway to AWS

#### Option A: Keep Custom Domain (Recommended)

```
tmalert.com
├── app.tmalert.com     → Vercel (unchanged)
├── api.tmalert.com     → AWS ALB → ECS/Lambda
└── Cookie: .tmalert.com (unchanged)
```

**Changes Required:**
- ✅ **Zero code changes** - Cookie domain already configured
- ✅ Update DNS records (api.tmalert.com → AWS ALB)
- ✅ Update CORS allowed origins (add AWS domain if needed)
- ✅ Update environment variables:
  - `DATABASE_URL` → RDS endpoint
  - `REDIS_URL` → ElastiCache endpoint
  - `SECRET_KEY` → AWS Secrets Manager
  - `MFA_CHALLENGE_SECRET_KEY` → AWS Secrets Manager

**AWS Infrastructure Example:**

```yaml
# CloudFormation / SAM Template
Resources:
  AlertSystemCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: tm-alert-cluster
  
  AlertSystemTask:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: tm-alert-backend
      NetworkMode: awsvpc
      RequiresCompatibilities:
        - FARGATE
      Cpu: 256
      Memory: 512
      ExecutionRoleArn: !Ref TaskExecutionRole
      ContainerDefinitions:
        - Name: backend
          Image: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/tm-alert-backend:latest
          PortMappings:
            - ContainerPort: 8000
          Environment:
            - Name: DATABASE_URL
              Value: !Sub postgresql://${DbUsername}:${DbPassword}@${Database.Endpoint}/${DbName}
            - Name: REDIS_URL
              Value: !Sub rediss://${ElastiCache.PrimaryEndpointAddress}:6379
          Secrets:
            - Name: SECRET_KEY
              ValueFrom: !Ref SecretKeySecret
            - Name: MFA_CHALLENGE_SECRET_KEY
              ValueFrom: !Ref MfaSecretKeySecret
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: !Ref LogGroup
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: tm-alert
  
  AlertSystemALB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Subnets:
        - !Ref PublicSubnet1
        - !Ref PublicSubnet2
      SecurityGroups:
        - !Ref ALBSecurityGroup
      Scheme: internet-facing
  
  AlertSystemTargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      VpcId: !Ref VPC
      Port: 8000
      Protocol: HTTP
      TargetType: ip
      HealthCheckPath: /health
  
  AlertSystemListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref AlertSystemALB
      Port: 443
      Protocol: HTTPS
      Certificates:
        - CertificateArn: !Ref CertificateArn
      DefaultActions:
        - Type: forward
          TargetGroupArn: !Ref AlertSystemTargetGroup
```

#### Option B: Temporary Domain Change (Not Recommended)

```
# If AWS domain is different (e.g., aws.tmalert.com)
tmalert.com
├── app.tmalert.com     → Vercel
└── aws.tmalert.com     → AWS ALB

# Cookie domain must be updated to:
domain=".tmalert.com"  # Root domain to cover all subdomains
```

**Changes Required:**
- ✅ Update backend cookie domain setting
- ✅ Update CORS allowed origins
- ✅ Update frontend API base URL

---

## 📝 Migration Checklist

### Phase 1: Current (Cross-Origin Workaround)

- [x] Add `refresh_token` field to `TokenResponse` schema
- [x] Add `refresh_token` field to `LoginSuccessResponse` schema
- [x] Modify `/login` endpoint to return `refresh_token` in response body
- [x] Modify `/refresh` endpoint to accept `refresh_token` from request body
- [x] Modify `/mfa/verify-login` endpoint to return `refresh_token` in body
- [x] Modify `/mfa/recovery-code/verify` endpoint to return `refresh_token` in body
- [x] Update cookie `SameSite` from `lax` to `none`
- [ ] Deploy backend from `dev-am` branch to Railway
- [ ] Test with frontend `dev-am` branch
- [ ] Verify page reload preserves session
- [ ] Verify MFA flow preserves session

### Phase 2: Custom Domain Setup

- [ ] Purchase custom domain (tmalert.com)
- [ ] Configure DNS records:
  - [ ] app.tmalert.com → Vercel
  - [ ] api.tmalert.com → Railway/AWS
- [ ] Update backend cookie configuration:
  - [ ] Set `domain=".tmalert.com"`
  - [ ] Change `samesite="lax"`
- [ ] Remove `refresh_token` from response bodies:
  - [ ] `TokenResponse` schema
  - [ ] `LoginSuccessResponse` schema
  - [ ] `/login` endpoint
  - [ ] `/refresh` endpoint
  - [ ] `/mfa/verify-login` endpoint
  - [ ] `/mfa/recovery-code/verify` endpoint
- [ ] Update `/refresh` endpoint to accept cookie ONLY
- [ ] Test cross-subdomain cookie sharing
- [ ] Create PR: `dev-am` → `main`
- [ ] Deploy from `main` branch

### Phase 3: AWS Migration (Optional)

- [ ] Set up AWS infrastructure:
  - [ ] VPC, subnets, security groups
  - [ ] ECS Fargate or Lambda
  - [ ] RDS PostgreSQL
  - [ ] ElastiCache Redis
  - [ ] Application Load Balancer
  - [ ] ACM SSL Certificate
- [ ] Migrate database from Railway to RDS
- [ ] Update DNS: api.tmalert.com → AWS ALB
- [ ] Update environment variables
- [ ] Test thoroughly in staging
- [ ] Cut over production traffic

---

## 🔒 Security Best Practices

### Current (Temporary)

1. **Token Handling:**
   - ✅ Refresh token in response body (cross-origin necessity)
   - ✅ Refresh token also in HttpOnly cookie (same-origin fallback)
   - ✅ Access token short-lived (1 hour)
   - ✅ Refresh token 7-day expiry

2. **Transport Security:**
   - ✅ HTTPS only (enforced by Railway)
   - ✅ Secure cookie flag set
   - ✅ SameSite=None (required for cross-origin)

3. **CSRF Protection:**
   - ✅ X-CSRF-Token header required
   - ✅ Cookie-based CSRF token
   - ⚠️ SameSite=None reduces protection (temporary)

4. **Token Rotation:**
   - ✅ Refresh token rotated on each use
   - ✅ Old tokens revoked in database
   - ✅ Database tracks all active tokens

5. **Audit Logging:**
   - ✅ All login attempts logged
   - ✅ Token refresh events logged
   - ✅ Logout events logged
   - ✅ MFA events logged

### Future (Custom Domain)

1. **Token Handling:**
   - ✅ Refresh token in HttpOnly cookie ONLY
   - ✅ Refresh token NEVER in response body
   - ✅ Access token short-lived (1 hour)
   - ✅ Refresh token 7-day expiry

2. **Transport Security:**
   - ✅ HTTPS only
   - ✅ Secure cookie flag
   - ✅ SameSite=Lax (better CSRF protection)

3. **CSRF Protection:**
   - ✅ X-CSRF-Token header
   - ✅ SameSite=Lax cookies
   - ✅ Full OWASP compliance

4. **XSS Protection:**
   - ✅ Refresh token inaccessible to JS (HttpOnly)
   - ✅ Full XSS immunity for refresh tokens

---

## 📊 Files Modified

### Current Implementation (dev-am branch)

| File | Changes | Purpose |
|------|---------|---------|
| `app/schemas.py` | Added `refresh_token` field to `TokenResponse` and `LoginSuccessResponse` | Enable response body delivery |
| `app/api/auth.py` | Modified `/login` to return `refresh_token` in body | Cross-origin support |
| `app/api/auth.py` | Modified `/refresh` to accept `refresh_token` from body | Cross-origin support |
| `app/api/auth.py` | Modified `/mfa/verify-login` to return `refresh_token` in body | Cross-origin support |
| `app/api/auth.py` | Modified `/mfa/recovery-code/verify` to return `refresh_token` in body | Cross-origin support |
| `app/api/auth.py` | Updated `_set_refresh_cookie()` to use `samesite="none"` | Cross-origin cookie support |

### Future Reversion (main branch after custom domain)

| File | Changes to Revert | Purpose |
|------|-------------------|---------|
| `app/schemas.py` | Remove `refresh_token` field | Security - no body exposure |
| `app/api/auth.py` | Remove `refresh_token` from `/login` response | Security - no body exposure |
| `app/api/auth.py` | Remove body acceptance from `/refresh` | Security - cookie-only |
| `app/api/auth.py` | Remove `refresh_token` from MFA endpoints | Security - no body exposure |
| `app/api/auth.py` | Update `_set_refresh_cookie()` to use `samesite="lax"` | Better CSRF protection |
| `app/api/auth.py` | Add `domain=".tmalert.com"` to cookie | Cross-subdomain support |

---

## 📚 References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 6265 - HTTP State Management Mechanism (Cookies)](https://tools.ietf.org/html/rfc6265)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [FastAPI Security Documentation](https://fastapi.tiangolo.com/security/)

---

## 📞 Support

For questions or issues related to backend authentication:

1. Check Railway deployment logs for errors
2. Verify environment variables are set correctly
3. Check database for refresh token records
4. Review audit logs for auth events

**Current Branch Status:**
- Backend: `dev-am` (commit `02f2356`)
- Frontend: `dev-am` (commit `5a329e3`)

**Next Steps:**
1. Deploy backend from `dev-am` to Railway
2. Test with frontend `dev-am` branch
3. Monitor logs for auth flow issues
4. Create PR when ready: `dev-am` → `main`

---

*Last Updated: March 12, 2026*  
*Author: AI Assistant (Qwen Code)*  
*Review Status: Pending user testing*

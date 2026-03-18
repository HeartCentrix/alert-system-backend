# TM Alert — Emergency Notification System
### Built by HeartCentrix for Taylor Morrison

---

## Overview

TM Alert is a web-based emergency notification platform that enables Taylor Morrison to send
multi-channel alerts (SMS, Email, Voice, Teams, Slack) to employees during
emergencies, with two-way safety check-in responses.

---

## Authentication & Single Sign-On (SSO)

TM Alert supports multiple authentication providers to integrate with your organization's identity infrastructure.

### 🔐 Supported Authentication Providers

| Provider | Description | Use Case |
|----------|-------------|----------|
| **Local** | Email/password stored in TM Alert | Fallback or standalone accounts |
| **Microsoft Entra ID** | OAuth 2.0 / OIDC with PKCE | Modern Azure AD / Microsoft 365 SSO |
| **LDAP/Active Directory** | LDAP v3 with TLS/SSL | On-premises Active Directory integration |

### ✨ SSO Features

- **Seamless Login**: Users authenticate with their existing Microsoft/AD credentials
- **Automatic User Provisioning**: First-time SSO users are auto-created in TM Alert
- **Role-Based Access**: Default role is `viewer` (admins can upgrade roles post-login)
- **Secure OAuth Flow**: Authorization Code with PKCE prevents token interception
- **State & Nonce Protection**: CSRF and replay attack prevention
- **Session Management**: JWT tokens with configurable expiration
- **MFA Support**: Microsoft MFA policies enforced at provider level
- **Password Security**: SSO users have no stored passwords (prevents password operations)

### 🚀 How SSO Works

#### Microsoft Entra ID Flow:
```
1. User clicks "Sign in with Microsoft" on login page
                ↓
2. Backend generates PKCE code verifier & challenge
   Stores OAuth state in Redis (10-minute expiry)
                ↓
3. Browser redirects to Microsoft OAuth 2.0 endpoint
   - Client ID, Tenant ID
   - PKCE challenge (S256)
   - State parameter (CSRF protection)
   - Nonce (replay protection)
                ↓
4. User authenticates with Microsoft (MFA enforced if configured)
                ↓
5. Microsoft redirects back to backend callback with auth code
                ↓
6. Backend exchanges code + PKCE verifier for ID token & access token
                ↓
7. Backend validates token signature, expiry, and nonce
                ↓
8. Backend extracts user info (email, name, OID)
   - If user exists: Log in
   - If new user: Auto-provision with VIEWER role
                ↓
9. Backend issues JWT access/refresh tokens
   Redirects to frontend with tokens in URL fragment
                ↓
10. Frontend stores tokens, user is authenticated
```

#### LDAP/Active Directory Flow:
```
1. User enters AD username and password on login form
                ↓
2. Backend connects to LDAP server with service account
                ↓
3. Backend searches for user with configured filter:
   (&(objectClass=user)(sAMAccountName={username}))
                ↓
4. Backend attempts to bind with user's DN and provided password
   - Success: Credentials valid
   - Failure: Invalid credentials
                ↓
5. Backend extracts user attributes (mail, givenName, sn)
                ↓
6. Backend auto-provisions user (if enabled) or logs in existing user
                ↓
7. Backend issues JWT tokens, user authenticated
```

### 🛡️ Security Measures

- **No Password Storage**: SSO users have `NULL` passwords in database
- **Password Reset Disabled**: SSO users cannot use password reset (must use provider)
- **Token Hashing**: OAuth state tokens hashed in Redis
- **Rate Limiting**: Login attempts rate-limited per IP
- **CSRF Protection**: State parameter validates OAuth callback
- **PKCE Required**: Prevents authorization code interception
- **HTTPS Enforced**: Redirect URIs must use HTTPS in production
- **Email Domain Validation**: Optional restriction to specific domains
- **Session Expiry**: Configurable token lifetimes

### 📦 Environment Configuration

#### Enable Authentication Providers

```env
# Comma-separated list: local, entra, ldap
AUTH_PROVIDERS=local,entra,ldap

# Individual provider toggles
ENTRA_ENABLED=true
LDAP_ENABLED=false
LOCAL_ENABLED=true
```

#### Microsoft Entra ID Setup

**Step 1: Register Application in Azure AD**

1. Go to [Azure Portal](https://portal.azure.com) → Azure Active Directory
2. Navigate to **App registrations** → **New registration**
3. Configure:
   - **Name**: `TM Alert`
   - **Supported account types**: "Accounts in this organizational directory only"
   - **Redirect URI**: 
     - Development: `http://localhost:8000/api/v1/auth/entra/callback`
     - Production: `https://yourdomain.com/api/v1/auth/entra/callback`

**Step 2: Configure Authentication Settings**

In Azure AD app registration:
1. Go to **Authentication** tab
2. Enable **Access tokens** and **ID tokens** under Implicit grant
3. Set **Default client type**: "Yes" (for PKCE)
4. Add redirect URI (must match `.env` exactly)

**Step 3: Create Client Secret**

1. Go to **Certificates & secrets** → **New client secret**
2. Description: `TM Alert Production`
3. Expires: 24 months (recommended)
4. **Copy the secret value immediately** (won't be shown again)

**Step 4: Configure API Permissions**

1. Go to **API permissions** → **Add a permission** → **Microsoft Graph**
2. Add **Delegated permissions**:
   - `openid` - Sign users in
   - `email` - View user's email
   - `profile` - View user's basic info
   - `User.Read` - Sign in and read user profile
3. Click **Grant admin consent** (if available)

**Step 5: Update Backend .env**

```env
# Microsoft Entra ID Configuration
ENTRA_CLIENT_ID="08c84453-d601-4450-8b68-9048a9beb7a1"
ENTRA_CLIENT_SECRET="JxT8Q~6lReMyZK7wEwesnkk1JA-co2sjoPVW_cOV"
ENTRA_TENANT_ID="5d7977d2-5eb6-4008-9db8-1d5b8e19367a"
ENTRA_REDIRECT_URI="http://localhost:8000/api/v1/auth/entra/callback"

# Optional: Restrict to specific email domains
ENTRA_ALLOWED_EMAIL_DOMAINS="taylormorrison.com"
```

**Step 6: Find Your Tenant ID**

1. Azure Portal → Azure Active Directory
2. Overview → **Tenant ID** (copy this value)

#### LDAP/Active Directory Setup

**Prerequisites:**
- Active Directory server with LDAPS (port 636) enabled
- Service account with read-only access to user directory
- User accounts with email, first name, last name attributes

**Step 1: Create Service Account**

In Active Directory Users and Computers:
1. Create new user: `tmalert-service`
2. Set password (never expires recommended)
3. Add to **Read-only Domain Controllers** group (or equivalent)
4. Grant **Read** permissions on user OU

**Step 2: Configure Backend .env**

```env
# LDAP Server Configuration
LDAP_SERVER_URL="ldaps://ad.taylormorrison.com:636"
LDAP_BIND_DN="cn=tmalert-service,ou=ServiceAccounts,dc=taylormorrison,dc=com"
LDAP_BIND_PASSWORD="YourServiceAccountPassword"

# User Search Configuration
LDAP_USER_SEARCH_BASE="ou=Employees,dc=taylormorrison,dc=com"
LDAP_USER_SEARCH_FILTER="(&(objectClass=user)(sAMAccountName={username}))"

# Attribute Mappings
LDAP_EMAIL_ATTRIBUTE="mail"
LDAP_FIRST_NAME_ATTRIBUTE="givenName"
LDAP_LAST_NAME_ATTRIBUTE="sn"

# Security Settings
LDAP_USE_TLS=true
LDAP_TLS_REQUIRE_CERT=demand
```

**Step 3: Test LDAP Connection**

```bash
# Install ldap-utils (Linux) or use ldp.exe (Windows)
ldapsearch -x -H ldaps://ad.taylormorrison.com:636 \
  -D "cn=tmalert-service,ou=ServiceAccounts,dc=taylormorrison,dc=com" \
  -w "password" \
  -b "ou=Employees,dc=taylormorrison,dc=com" \
  "(sAMAccountName=testuser)" mail givenName sn
```

### 🔧 Role Assignment for SSO Users

**Default Behavior:**
- All SSO users get `viewer` role on first login
- Users are auto-provisioned if they don't exist

**Upgrade User Roles:**

1. Admin logs into TM Alert
2. Navigate to **People** → Find the SSO user
3. Click **Edit** → Change role to `manager`, `admin`, or `super_admin`
4. Save changes

**Future Logins:**
- User's role is preserved from database
- No automatic role changes on subsequent logins

### 🚫 SSO User Restrictions

SSO users **cannot**:
- Reset password via `/forgot-password` (must use Microsoft/AD password reset)
- Change password in settings (password managed by provider)
- Disable MFA (MFA enforced at provider level)
- Convert to local authentication

If an SSO user needs password operations:
1. Admin must create a new local account for them
2. Or user must reset password in Microsoft/AD portal

### 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     TM Alert Frontend                        │
│                   (React + Vite - Port 3000)                 │
└────────────────┬────────────────────────────────────────────┘
                 │
                 │ HTTP Requests
                 ↓
┌─────────────────────────────────────────────────────────────┐
│                     TM Alert Backend                         │
│                  (FastAPI - Port 8000)                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Authentication Providers                            │   │
│  │  • Local (email/password)                            │   │
│  │  • Entra ID (OAuth 2.0 / OIDC + PKCE)                │   │
│  │  • LDAP (Active Directory)                           │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  OAuth State Storage (Redis)                         │   │
│  │  • PKCE code verifiers                               │   │
│  │  • State parameters (CSRF protection)                │   │
│  │  • Nonce values (replay protection)                  │   │
│  └──────────────────────────────────────────────────────┘   │
└────────┬─────────────────────────────────────────────────────┘
         │
         │ OAuth Redirects
         ↓
┌─────────────────────────────────────────────────────────────┐
│              Microsoft Entra ID (Azure AD)                   │
│  • User Authentication                                       │
│  • MFA Enforcement                                           │
│  • Token Issuance                                            │
└─────────────────────────────────────────────────────────────┘
         OR
         │ LDAP Bind Request
         ↓
┌─────────────────────────────────────────────────────────────┐
│              On-Premises Active Directory                    │
│  • User Credential Validation                                │
│  • Attribute Lookup (mail, name)                             │
└─────────────────────────────────────────────────────────────┘
```

### 📝 Troubleshooting

**"Invalid redirect_uri" from Microsoft:**
- Ensure redirect URI in Azure AD matches `.env` **exactly**
- Check for trailing slashes (should not have one)
- Verify protocol (http vs https)

**"SSO user cannot reset password":**
- This is expected behavior
- SSO users must reset password in Microsoft/AD portal
- Frontend shows appropriate error message

**LDAP connection timeout:**
- Verify LDAPS port (636) is open from backend to AD server
- Check firewall rules
- Ensure certificate is valid (or set `LDAP_TLS_REQUIRE_CERT=allow` for testing)

**User sees "Password reset is disabled":**
- User is authenticated via SSO
- Password managed by Microsoft/AD
- Direct user to provider's password reset portal

---

## Deployment Model: Single-Tenant

**This application is designed as a single-tenant system for Taylor Morrison only.**

### Architecture Decisions:

- **No multi-tenancy isolation** - All data belongs to Taylor Morrison
- **No organisation_id/tenant_id** fields on database models
- **No cross-organisation access controls** - Not needed for single customer

---

## Tech Stack

- **Backend**: Python 3.11 + FastAPI
- **Database**: PostgreSQL 16
- **Cache / Queue Broker**: Redis 7
- **Background Tasks**: Celery + Celery Beat
- **SMS / Voice**: Twilio
- **Email**: AWS SES + SMTP
- **Auth**: JWT with MFA support (email + password + TOTP)

---

## Project Structure

```
tm_alert/
├── app/
│   ├── main.py              # FastAPI app, startup, routes
│   ├── config.py            # Environment settings
│   ├── database.py          # SQLAlchemy engine + session
│   ├── models.py            # All database models
│   ├── schemas.py           # Pydantic request/response schemas
│   ├── tasks.py             # Celery tasks (notification dispatch)
│   ├── celery_app.py        # Celery configuration
│   ├── api/
│   │   ├── auth.py          # Login, logout, password reset
│   │   ├── users.py         # People management + CSV import
│   │   ├── groups_locations_templates.py
│   │   ├── notifications.py # Incidents + Notifications + Responses
│   │   ├── webhooks.py      # Twilio inbound SMS/Voice callbacks
│   │   └── dashboard.py     # Stats + Map data
│   ├── core/
│   │   ├── security.py      # JWT + password hashing
│   │   └── deps.py          # Auth dependencies + role guards
│   └── services/
│       └── messaging.py     # Twilio + SES + Webhook services
├── alembic/                 # Database migrations
├── docker-compose.yml       # Local dev environment
├── Dockerfile
├── railway.toml             # Railway deployment config
├── Procfile                 # For Railway/Heroku
├── requirements.txt
└── .env.example
```

---

## Quick Start (Local Dev)

### 1. Clone and Setup

```bash
git clone <your-repo>
cd tm_alert
cp .env.example .env
# Edit .env with your Twilio, AWS, and other credentials
```

### 2. Run with Docker Compose (Recommended)

```bash
docker-compose up --build
```

This starts:
- PostgreSQL on port 5432
- Redis on port 6379
- FastAPI on port 8000
- Celery worker
- Celery beat (scheduled tasks)

Access the API docs at: http://localhost:8000/api/docs

### 3. Run Without Docker

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start PostgreSQL and Redis (must be running)

# Run database migrations
alembic upgrade head

# Start the API
uvicorn app.main:app --reload --port 8000

# In a separate terminal - Start Celery worker
celery -A app.celery_app worker --loglevel=info

# In another terminal - Start Celery beat (scheduler)
celery -A app.celery_app beat --loglevel=info
```

---

## Default Admin Login

On first startup, a default admin account is created with:
- **Email:** `admin@tmalert.com`
- **Password:** A secure random password generated at runtime

The bootstrap password is written to `/run/secrets/bootstrap_pw` on first boot. If that path is not available, check the application logs on **first boot only** for the password.

**⚠️ You will be forced to change the password on first login.**

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/auth/login | Login |
| POST | /api/v1/auth/refresh | Refresh token |
| POST | /api/v1/auth/logout | Logout |
| POST | /api/v1/auth/forgot-password | Request password reset |
| POST | /api/v1/auth/reset-password | Reset password |
| GET | /api/v1/auth/me | Get current user |

### People (Users)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/users | List users (with search/filter) |
| POST | /api/v1/users | Create user |
| GET | /api/v1/users/{id} | Get user |
| PUT | /api/v1/users/{id} | Update user |
| DELETE | /api/v1/users/{id} | Delete user |
| POST | /api/v1/users/import/csv | Bulk import from CSV |

### Groups
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/groups | List groups |
| POST | /api/v1/groups | Create group |
| GET | /api/v1/groups/{id} | Get group with members |
| PUT | /api/v1/groups/{id} | Update group |
| DELETE | /api/v1/groups/{id} | Delete group |
| POST | /api/v1/groups/{id}/members | Add members |
| DELETE | /api/v1/groups/{id}/members/{user_id} | Remove member |

### Locations
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/locations | List locations |
| POST | /api/v1/locations | Create location |
| PUT | /api/v1/locations/{id} | Update location |
| DELETE | /api/v1/locations/{id} | Delete location |

### Notifications
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/notifications | List notifications |
| POST | /api/v1/notifications | Create + send notification |
| GET | /api/v1/notifications/{id} | Get notification details |
| POST | /api/v1/notifications/{id}/send | Send draft |
| POST | /api/v1/notifications/{id}/cancel | Cancel scheduled |
| GET | /api/v1/notifications/{id}/delivery | Delivery logs |
| GET | /api/v1/notifications/{id}/responses | Employee responses |
| POST | /api/v1/notifications/{id}/respond | Submit response (web) |

### Incidents
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/incidents | List incidents |
| POST | /api/v1/incidents | Create incident |
| GET | /api/v1/incidents/{id} | Get incident |
| PUT | /api/v1/incidents/{id} | Update/resolve incident |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/dashboard/stats | Stats (users, groups, active incidents) |
| GET | /api/v1/dashboard/map-data | Location + employee count for map |
| GET | /api/v1/dashboard/notification-activity | Daily notification counts |

### Webhooks (Twilio callbacks)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/webhooks/sms/inbound | Inbound SMS from employees |
| POST | /api/v1/webhooks/sms/status | SMS delivery status updates |
| POST | /api/v1/webhooks/voice/response | Voice call keypress responses |

---

## CSV Import Format

To bulk import employees, use a CSV with these columns:
```
first_name, last_name, email, phone, department, title, employee_id, role
```

Roles: `super_admin`, `admin`, `manager`, `viewer` (default: viewer)

**Password Handling:**
- New users imported via CSV are automatically sent a **welcome email** with their temporary password
- The email includes login URL and security reminders to change password after first login
- Ensure AWS SES is configured with valid credentials for emails to be sent

---

## Sending a Notification (API Example)

```json
POST /api/v1/notifications
Authorization: Bearer <token>

{
  "title": "Severe Weather Warning",
  "message": "A severe thunderstorm warning has been issued for the Phoenix area. All outdoor work must stop immediately. Reply 1 if safe, 2 if you need help.",
  "subject": "⚠️ URGENT: Severe Weather Warning",
  "channels": ["sms", "email", "voice"],
  "target_all": false,
  "target_group_ids": [1, 2],
  "response_required": true,
  "response_deadline_minutes": 30
}
```

---

## Employee Response Options

Employees can respond via:

**SMS Reply:**
- `1` or `SAFE` → Marked as safe
- `2` or `HELP` → Marked as needing help

**Voice Call:**
- Press `1` → Safe
- Press `2` → Need help

**Web Portal:**
- Click Safe / Need Help buttons

---

## Deploy to Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway add postgresql
railway add redis
railway up

# Set environment variables
railway variables set TWILIO_ACCOUNT_SID=xxx
railway variables set TWILIO_AUTH_TOKEN=xxx
# ... etc
```

---

## Deploy to AWS (ECS)

1. Push Docker image to ECR
2. Create ECS cluster with Fargate
3. Create RDS PostgreSQL instance
4. Create ElastiCache Redis cluster
5. Set environment variables in ECS task definition
6. Configure Application Load Balancer

---

## Twilio Webhook Configuration

After deploying, configure in Twilio Console:

1. Go to Phone Numbers → Active Numbers → Your Number
2. Set "A Message Comes In" webhook to:
   `https://your-domain.com/api/v1/webhooks/sms/inbound`
3. Set "Status Callback URL" to:
   `https://your-domain.com/api/v1/webhooks/sms/status`

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| DATABASE_URL | Yes | PostgreSQL connection string |
| REDIS_URL | Yes | Redis connection string |
| SECRET_KEY | Yes | JWT signing key (min 32 chars) |
| TWILIO_ACCOUNT_SID | Yes | Twilio Account SID |
| TWILIO_AUTH_TOKEN | Yes | Twilio Auth Token |
| TWILIO_FROM_NUMBER | Yes | Your Twilio phone number |
| AWS_ACCESS_KEY_ID | For email | AWS credentials for SES |
| AWS_SECRET_ACCESS_KEY | For email | AWS credentials for SES |
| SES_FROM_EMAIL | For email | Verified SES sender email |
| GOOGLE_MAPS_API_KEY | Optional | For map features |

---

Built by HeartCentrix — www.heartcentrix.com

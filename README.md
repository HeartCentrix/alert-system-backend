# TM Alert — Emergency Notification System
### Built by HeartCentrix for Taylor Morrison

---

## Overview

TM Alert is a web-based emergency notification platform that enables Taylor Morrison to send
multi-channel alerts (SMS, Email, Voice, Teams, Slack) to employees during
emergencies, with two-way safety check-in responses.

---

## Tech Stack

- **Backend**: Python 3.11 + FastAPI
- **Database**: PostgreSQL 16
- **Cache / Queue Broker**: Redis 7
- **Background Tasks**: Celery
- **SMS / Voice**: Twilio
- **Email**: AWS SES
- **Auth**: JWT (email + password)

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

On first startup, a default admin is created:

```
Email:    admin@tmalert.com
Password: Admin@123456
```

**Change this immediately after first login.**

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

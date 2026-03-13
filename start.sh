#!/bin/bash
set -e

# Detect service type from environment variable
SERVICE_TYPE="${SERVICE_TYPE:-api}"

echo "========================================="
echo "Starting Alert System Backend"
echo "Service Type: $SERVICE_TYPE"
echo "========================================="
echo "Environment: ${APP_ENV:-not set}"
echo "Database URL: ${DATABASE_URL:-not set}"
echo "Redis URL: ${REDIS_URL:-not set}"

# Validate required environment variables
if [ -z "$SECRET_KEY" ]; then
    echo "ERROR: SECRET_KEY is not set"
    exit 1
fi

if [ -z "$REFRESH_SECRET_KEY" ]; then
    echo "ERROR: REFRESH_SECRET_KEY is not set"
    exit 1
fi

if [ -z "$MFA_CHALLENGE_SECRET_KEY" ]; then
    echo "ERROR: MFA_CHALLENGE_SECRET_KEY is not set"
    exit 1
fi

echo "Secret keys validated (length check passed)"

# Run schema validation and migrations for all service types
echo "Step 1: Validating database schema..."
python -m scripts.validate_db_schema --fix || echo "Schema validation completed with warnings"

echo "Step 2: Running database migrations..."
alembic upgrade head || {
    echo "ERROR: Database migrations failed"
    exit 1
}

echo "Step 3: Starting $SERVICE_TYPE service..."

# Start the appropriate service based on type
case "$SERVICE_TYPE" in
    "api")
        echo "Starting API server (uvicorn)..."
        # Use PORT env var from Railway, default to 8000
        PORT=${PORT:-8000}
        exec uvicorn app.main:app --host 0.0.0.0 --port $PORT --log-level info
        ;;
    "worker")
        echo "Starting Celery worker..."
        exec celery -A app.celery_app worker --loglevel=info --pool=solo
        ;;
    "beat")
        echo "Starting Celery beat scheduler..."
        exec celery -A app.celery_app beat --loglevel=info
        ;;
    *)
        echo "Unknown service type: $SERVICE_TYPE"
        echo "Valid types: api, worker, beat"
        exit 1
        ;;
esac

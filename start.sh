#!/bin/bash
set -e

# Detect service type from environment variable
SERVICE_TYPE="${SERVICE_TYPE:-api}"

echo "========================================="
echo "Starting Alert System Backend"
echo "Service Type: $SERVICE_TYPE"
echo "========================================="

# Run schema validation and migrations for all service types
echo "Step 1: Validating database schema..."
python -m scripts.validate_db_schema --fix || true

echo "Step 2: Running database migrations..."
alembic upgrade head

echo "Step 3: Starting $SERVICE_TYPE service..."

# Start the appropriate service based on type
case "$SERVICE_TYPE" in
    "api")
        echo "Starting API server (uvicorn)..."
        exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level info
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

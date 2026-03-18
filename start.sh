#!/bin/bash
set -e

# Detect service type from environment variable
SERVICE_TYPE="${SERVICE_TYPE:-api}"

echo "========================================="
echo "Starting Alert System Backend"
echo "Service Type: $SERVICE_TYPE"
echo "========================================="

# Run database initialization for all service types
echo "Step 1: Initializing database (creating enums and tables)..."
python -m app.db_init || true

echo "Step 2: Starting $SERVICE_TYPE service..."

# Start the appropriate service based on type
case "$SERVICE_TYPE" in
    "api")
        echo "Starting API server (uvicorn) on port ${PORT:-8000}..."
        exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --log-level info
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

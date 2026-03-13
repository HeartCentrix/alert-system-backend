web: bash -c 'uvicorn app.main:app --host 0.0.0.0 --port $PORT'
worker: celery -A app.celery_app worker --loglevel=info --concurrency=2
beat: celery -A app.celery_app beat --loglevel=info

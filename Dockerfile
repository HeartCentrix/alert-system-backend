FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-prod.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements-prod.txt

# --- Production image ---

FROM python:3.11-slim

WORKDIR /app

# 1. Create a non-root user with fixed UID/GID
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/false --create-home appuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

# 2. Copy application code and set ownership
COPY --chown=appuser:appgroup . .

# 3. Make startup script executable
RUN sed -i 's/\r$//' start.sh && \     
    chmod +x start.sh

# 4. Create tmp directory for celerybeat schedule with proper permissions
RUN mkdir -p /tmp && chown appuser:appgroup /tmp

# 5. Create secrets directory for bootstrap password
RUN mkdir -p /run/secrets && chmod 1777 /run/secrets

# 6. Switch to non-root user BEFORE CMD
USER appuser

EXPOSE 8000

# Use startup script that runs migrations before starting
# Railway injects $PORT — start.sh reads it via ${PORT:-8000}
CMD ["/app/start.sh"]

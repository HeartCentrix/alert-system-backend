# =============================================================================
# TM Alert - Production Dockerfile (Multi-stage, Security Hardened)
# Follows OWASP Docker Security Cheat Sheet
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build Frontend
# -----------------------------------------------------------------------------
FROM node:20-alpine AS frontend-builder

WORKDIR /app

# Install dependencies with security checks
COPY alert-system-frontend/package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# Copy source and build
COPY alert-system-frontend/ ./
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: Backend (Python FastAPI)
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS backend

WORKDIR /app

# Create non-root user for security
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy and install Python dependencies
COPY Alert-system-backend/requirements*.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements-prod.txt

# Copy backend code
COPY Alert-system-backend/ ./

# Set proper permissions
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# -----------------------------------------------------------------------------
# Stage 3: Production (Nginx + Frontend + Backend)
# -----------------------------------------------------------------------------
FROM nginx:alpine AS production

# Install OpenSSL for health checks
RUN apk add --no-cache openssl

# Create non-root user
RUN addgroup -g 1001 -S nginx && \
    adduser -S -D -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx

# Copy custom nginx config with security headers
COPY Alert-system-backend/nginx.conf /etc/nginx/nginx.conf

# Copy built frontend assets
COPY --from=frontend-builder /app/dist /usr/share/nginx/html

# Set proper permissions
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

# Remove default nginx config
RUN rm -rf /etc/nginx/conf.d/default.conf

# Security: Remove unnecessary files
RUN rm -rf /etc/nginx/html/*

USER nginx

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]

# -----------------------------------------------------------------------------
# Stage 4: Development (with hot reload)
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS development

WORKDIR /app

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY Alert-system-backend/requirements*.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt -r requirements-test.txt

# Copy backend code
COPY Alert-system-backend/ ./

# Install frontend dependencies (for development)
COPY alert-system-frontend/package*.json /frontend/
WORKDIR /frontend
RUN npm install

EXPOSE 8000 3000

# Development command (will be overridden in docker-compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

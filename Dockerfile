# Multi-stage Dockerfile for doctorhide Django application

# Stage 1: Builder
FROM python:3.13-slim as builder

WORKDIR /app

# Install build dependencies and PostgreSQL client libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt


# Stage 2: Runtime
FROM python:3.13-slim

WORKDIR /app

# Install runtime dependencies only (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Create a non-root user to run the app
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app

# Collect static files (generates staticfiles/ with compressed assets)
RUN python manage.py collectstatic --noinput

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Default command: run gunicorn with threaded workers so idle/slow connections
# don't tie up (and time out) a whole worker. --timeout 120 quiets the spurious
# "WORKER TIMEOUT / no URI read" log from empty keep-alive/probe sockets.
# Can be overridden (e.g., for management commands like migrate)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", \
     "--workers", "2", "--worker-class", "gthread", "--threads", "4", \
     "--timeout", "120", \
     "doctorhide.wsgi:application"]

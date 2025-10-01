# Multi-stage Dockerfile for PQCTransitSecure Platform
# liboqs is intentionally excluded and must be built locally on each machine

FROM python:3.11-slim as base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt backend/requirements.txt* ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt || \
    pip install --no-cache-dir \
        fastapi==0.104.1 \
        uvicorn==0.24.0 \
        cryptography==41.0.5 \
        sqlalchemy==2.0.23 \
        pydantic==2.4.2 \
        bcrypt==4.0.1 \
        PyJWT==2.8.0 \
        httpx==0.25.1 \
        python-multipart==0.0.20 \
        websockets==12.0

# Production stage
FROM base as production

# Copy application code
COPY backend/ ./backend/
COPY index.html sw.js favicon.ico start_https_server.py ./

# Create necessary directories
RUN mkdir -p /app/data /app/logs

# Expose ports
# 3001: Quantum Service
# 4000: Main App
# 8000: Frontend
EXPOSE 3001 4000 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:4000/health || exit 1

# Default command (overridden by docker-compose)
CMD ["python", "-m", "uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "4000"]

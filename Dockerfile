# ──────────────────────────────────────────────────────
# NetWatch — Production Docker Image
# ──────────────────────────────────────────────────────
# Build:   docker build -t netwatch .
# Run:     docker run -p 5000:5000 -v netwatch-data:/data netwatch
# ──────────────────────────────────────────────────────

FROM python:3.11-slim AS base

# System deps for scapy + pcap
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev tcpdump iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn==21.2.0

# Copy application code
COPY . .

# Env defaults
ENV NETWATCH_ENV=production \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    DATABASE_PATH=/data/netwatch.db \
    PYTHONUNBUFFERED=1

# Persist database
VOLUME ["/data"]

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/status')"

# Production: gunicorn with 2 workers (adjust to CPU count)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "backend.app:create_app()"]

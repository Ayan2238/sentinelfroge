# ─────────────────────────────────────────────────────────────────
# SentinelForge — Multi-stage Docker image
# ─────────────────────────────────────────────────────────────────
# Build:  docker build -t sentinelforge:latest .
# Run:    docker run --rm -it sentinelforge:latest sf scan example.com
# ─────────────────────────────────────────────────────────────────

# ── Stage 1: Builder ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libssl-dev libffi-dev git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY sentinelforge/ ./sentinelforge/
COPY configs/ ./configs/

# Install the package with optional full deps
RUN pip install --upgrade pip && \
    pip install --no-cache-dir ".[full]" --target /app/deps

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: run as non-root
RUN useradd -m -s /bin/bash -u 1001 sentinel

# Copy installed dependencies
COPY --from=builder /app/deps /usr/local/lib/python3.12/site-packages/

# Copy configs
COPY configs/ /etc/sentinelforge/

# Create output directory
RUN mkdir -p /output && chown sentinel:sentinel /output

# Switch to non-root user
USER sentinel
WORKDIR /home/sentinel

# Environment
ENV SF_OUTPUT_DIR=/output
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default command
ENTRYPOINT ["sf"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD sf version || exit 1

LABEL org.opencontainers.image.title="SentinelForge"
LABEL org.opencontainers.image.description="Professional Security Assessment Framework"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"

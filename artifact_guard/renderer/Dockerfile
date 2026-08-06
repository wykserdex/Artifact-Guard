FROM python:3.12-slim

WORKDIR /app

# Install Playwright dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for renderer
RUN useradd --create-home --uid 10001 worker

COPY pyproject.toml .
RUN pip install --no-cache-dir playwright httpx structlog

# Install Playwright browsers
RUN playwright install chromium
RUN playwright install-deps chromium

COPY renderer/ ./renderer/
COPY shared/ ./shared/

# Change ownership to worker
RUN chown -R worker:worker /app

USER worker

ENV HOME=/home/worker
ENV PYTHONPATH=/app

CMD ["python", "-m", "renderer.worker"]

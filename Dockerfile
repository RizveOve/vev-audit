# Vev Audit API + dashboard. Chromium is installed by Playwright itself, so the
# browser build always matches the installed Playwright Python version.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    VEV_DATABASE_PATH=/app/data/vev_audit.db \
    PORT=8000

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt \
 && playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*

COPY vev_audit ./vev_audit
COPY frontend ./frontend

RUN useradd --create-home --uid 10001 vev \
 && mkdir -p /app/data \
 && chown -R vev:vev /app/data
USER vev

VOLUME ["/app/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/api/health', timeout=4)"

# One worker: scans run in-process and share a single Chromium instance and SQLite file.
CMD ["sh", "-c", "exec uvicorn vev_audit.main:app --host 0.0.0.0 --port ${PORT} --no-server-header"]

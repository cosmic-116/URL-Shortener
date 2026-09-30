#!/bin/bash
# Azure App Service startup script for Flask + Gunicorn
set -e

echo "=== Snip URL Shortener — Azure Startup ==="

# Fail fast if FLASK_SECRET_KEY is empty in production
if [ -z "$FLASK_SECRET_KEY" ]; then
    echo "FATAL: FLASK_SECRET_KEY environment variable is not set. Refusing to start." >&2
    exit 1
fi

# Fail fast if required email configuration variables are missing for acs or smtp
MAIL_BACKEND_LOWER=$(echo "${MAIL_BACKEND:-acs}" | tr '[:upper:]' '[:lower:]')
if [ "$MAIL_BACKEND_LOWER" = "acs" ] || [ "$MAIL_BACKEND_LOWER" = "smtp" ]; then
    MISSING_MAIL_VARS=""
    [ -z "$SMTP_HOST" ] && MISSING_MAIL_VARS="$MISSING_MAIL_VARS SMTP_HOST"
    [ -z "$SMTP_PORT" ] && MISSING_MAIL_VARS="$MISSING_MAIL_VARS SMTP_PORT"
    [ -z "$SMTP_USER" ] && MISSING_MAIL_VARS="$MISSING_MAIL_VARS SMTP_USER"
    [ -z "$SMTP_PASSWORD" ] && MISSING_MAIL_VARS="$MISSING_MAIL_VARS SMTP_PASSWORD"
    FROM_CHECK="${MAIL_FROM:-$SMTP_FROM}"
    [ -z "$FROM_CHECK" ] && MISSING_MAIL_VARS="$MISSING_MAIL_VARS SMTP_FROM"
    if [ -n "$MISSING_MAIL_VARS" ]; then
        echo "FATAL: Missing required email configuration variables:$MISSING_MAIL_VARS. Refusing to start." >&2
        exit 1
    fi
fi

# Azure's persistent storage is /home — DB lives there by default
# NOTE: Azure /home is network-backed (CIFS/NFS). SQLite WAL mode on network storage carries
# risks of stale locks under high concurrent writes. If lock contention occurs, set
# DB_JOURNAL_MODE=DELETE or migrate to a managed database (PostgreSQL) for multi-instance scaling.
export DATA_DIR="${DATA_DIR:-/home/data}"
mkdir -p "$DATA_DIR"

# Optional database reset trigger
RESET_DB_LOWER=$(echo "${RESET_DB:-false}" | tr '[:upper:]' '[:lower:]')
if [ "$RESET_DB_LOWER" = "true" ] || [ "$RESET_DB_LOWER" = "1" ] || [ "$RESET_DB_LOWER" = "yes" ]; then
    echo "RESET_DB flag detected: wiping existing database in $DATA_DIR..."
    rm -f "$DATA_DIR/database.db" "$DATA_DIR/database.db-wal" "$DATA_DIR/database.db-shm"
fi

# Initialize database schema (idempotent)
echo "Initializing database at $DATA_DIR/database.db ..."
python -c "import app; app.db.init_db(app.app); print('Database ready.')"

# Start gunicorn
# --workers 2: sufficient for App Service B1/P1 without memory exhaustion
# --threads 4: handles concurrent I/O within each worker process
# --timeout 120: generous timeout for synchronous operations
# --forwarded-allow-ips="*": Safe on Azure App Service Linux because external traffic
#   passes exclusively through the secure Azure front-end reverse proxy infrastructure.
# --access-logfile -: pipes access logs to stdout for Azure Log Stream
exec gunicorn \
    --bind=0.0.0.0:${PORT:-8000} \
    --workers=2 \
    --threads=4 \
    --timeout=120 \
    --forwarded-allow-ips="*" \
    --access-logfile=- \
    --error-logfile=- \
    app:app

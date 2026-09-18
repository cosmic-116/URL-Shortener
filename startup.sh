#!/bin/bash
# Azure App Service startup script for Flask + Gunicorn
set -e

echo "=== Snip URL Shortener — Azure Startup ==="

# Azure's persistent storage is /home — DB must live there
export DATA_DIR="${DATA_DIR:-/home/data}"
mkdir -p "$DATA_DIR"

# Initialize the database schema (idempotent — uses CREATE IF NOT EXISTS)
echo "Initializing database at $DATA_DIR/database.db ..."
python -c "import app; app.db.init_db(app.app); print('Database ready.')"

# Start gunicorn
# --workers 2: enough for B1 tier without exhausting RAM
# --threads 4: handle concurrent requests within each worker
# --timeout 120: generous timeout for slow QR generation
# --access-logfile -: pipe access logs to stdout for Azure Log Stream
exec gunicorn \
    --bind=0.0.0.0:${PORT:-8000} \
    --workers=2 \
    --threads=4 \
    --timeout=120 \
    --access-logfile=- \
    --error-logfile=- \
    app:app

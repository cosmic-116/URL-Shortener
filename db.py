import sqlite3
from flask import g
import os

# Use an absolute path relative to this file to avoid working directory issues
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# On Azure App Service (Linux), /home is the only persistent directory.
# Locally, fall back to the project directory.
DATA_DIR = os.environ.get('DATA_DIR', BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE = os.path.join(DATA_DIR, 'database.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row 
        # Enable foreign key enforcement for cascading deletes
        db.execute("PRAGMA foreign_keys = ON;")
    return db

def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def upgrade_db(db_conn):
    """Safely adds missing columns to tables if they do not exist."""
    try:
        cursor = db_conn.execute("PRAGMA table_info(links)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        new_cols = [
            ("ad_type", "TEXT DEFAULT 'network'"),
            ("custom_ad_url", "TEXT DEFAULT ''"),
            ("custom_ad_title", "TEXT DEFAULT ''"),
            ("custom_ad_desc", "TEXT DEFAULT ''"),
            ("custom_ad_media_type", "TEXT DEFAULT 'link'")
        ]
        for col_name, col_def in new_cols:
            if col_name not in existing_cols:
                db_conn.execute(f"ALTER TABLE links ADD COLUMN {col_name} {col_def};")
        db_conn.commit()
    except Exception:
        pass

def init_db(app):
    """Initializes the database schema if it doesn't exist and runs migrations."""
    with app.app_context():
        db = get_db()
        with open(os.path.join(BASE_DIR, 'schema.sql'), 'r') as f:
            db.executescript(f.read())
        upgrade_db(db)
        db.commit()

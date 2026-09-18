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

def init_db(app):
    """Initializes the database schema if it doesn't exist."""
    with app.app_context():
        db = get_db()
        with open(os.path.join(BASE_DIR, 'schema.sql'), 'r') as f:
            db.executescript(f.read())
        db.commit()

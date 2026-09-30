"""
Resets the Snip database by removing SQLite database files and reinitializing a clean schema.
Usage:
    python reset_db.py
"""
import os
import sys

from db import DATABASE, init_db

def reset():
    print(f"Resetting database at: {DATABASE}")
    deleted = 0
    for ext in ('', '-wal', '-shm'):
        p = f"{DATABASE}{ext}"
        if os.path.exists(p):
            try:
                os.remove(p)
                print(f"  Removed: {p}")
                deleted += 1
            except Exception as e:
                print(f"  Error removing {p}: {e}", file=sys.stderr)
    if deleted == 0:
        print("  No existing database files found.")
    print("Reinitializing fresh schema...")
    init_db()
    print("Database reset successfully! All old entries deleted and fresh schema ready.")

if __name__ == '__main__':
    reset()

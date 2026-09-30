import sqlite3
import os
import logging
from flask import g

logger = logging.getLogger("snip.db")

# Use an absolute path relative to this file to avoid working directory issues
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Persistent storage configuration
DATA_DIR = os.environ.get('DATA_DIR', BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE = os.path.join(DATA_DIR, 'database.db')

DB_TIMEOUT = 5.0  # Unified 5-second timeout for lock acquisition

def get_db():
    """Returns the request-scoped database connection."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, timeout=DB_TIMEOUT)
        db.row_factory = sqlite3.Row
        # Per-connection PRAGMAs
        db.execute("PRAGMA foreign_keys = ON;")
        db.execute("PRAGMA busy_timeout = 5000;")
        db.execute("PRAGMA synchronous = NORMAL;")
    return db

def close_connection(exception=None):
    """Closes the active database connection at the end of the request context."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def cleanup_stale_nonces(db_conn):
    """Purges expired ad nonces older than 10 minutes to prevent database bloat."""
    try:
        cur = db_conn.execute(
            "DELETE FROM ad_nonces WHERE created_at < datetime('now', '-10 minutes')"
        )
        if cur.rowcount > 0:
            db_conn.commit()
            logger.debug("Cleaned up %d expired ad nonces", cur.rowcount)
    except Exception as e:
        logger.warning("Nonce cleanup encountered error: %s", e)

def cleanup_stale_records(db_conn):
    """Periodic maintenance: purges stale nonces, expired OTPs, clears pending payloads, and prunes mail counters."""
    cleanup_stale_nonces(db_conn)
    try:
        # Clear pending_payload on consumed OTPs or 15 minutes past expiry (Refinement 9)
        db_conn.execute("""
            UPDATE email_otps 
            SET pending_payload = NULL 
            WHERE pending_payload IS NOT NULL 
              AND (consumed_at IS NOT NULL OR expires_at < datetime('now', '-15 minutes'))
        """)
        # Purge OTP rows older than 24h
        db_conn.execute("DELETE FROM email_otps WHERE created_at < datetime('now', '-24 hours')")
        
        # Prune mail counters older than 48h (days), 2h (hours), 5m (minutes)
        cutoff_day = db_conn.execute("SELECT strftime('%Y-%m-%d', 'now', '-2 days')").fetchone()[0]
        cutoff_hour = db_conn.execute("SELECT strftime('%Y-%m-%d-%H', 'now', '-2 hours')").fetchone()[0]
        cutoff_min = db_conn.execute("SELECT strftime('%Y-%m-%d-%H-%M', 'now', '-5 minutes')").fetchone()[0]
        db_conn.execute("DELETE FROM mail_counters WHERE bucket LIKE 'd:%' AND bucket < ('d:' || ?)", (cutoff_day,))
        db_conn.execute("DELETE FROM mail_counters WHERE bucket LIKE 'h:%' AND bucket < ('h:' || ?)", (cutoff_hour,))
        db_conn.execute("DELETE FROM mail_counters WHERE bucket LIKE 'm:%' AND bucket < ('m:' || ?)", (cutoff_min,))
        db_conn.commit()
    except Exception as e:
        logger.warning("Periodic records cleanup encountered error: %s", e)

def get_earnings(conn, uid):
    """
    Computes all user ad monetization aggregates in a single performant query.
    Values stored in integer micro-dollars (amount_micros) and converted to dollars for display.
    """
    try:
        row = conn.execute('''
            SELECT 
                COALESCE(SUM(amount_micros), 0) AS total_micros,
                COALESCE(SUM(CASE WHEN amount_micros > 0 THEN amount_micros ELSE 0 END), 0) AS network_micros,
                COALESCE(SUM(CASE WHEN amount_micros < 0 THEN ABS(amount_micros) ELSE 0 END), 0) AS custom_micros
            FROM ad_ledger
            WHERE owner_id = ?
        ''', (uid,)).fetchone()
    except sqlite3.OperationalError as e:
        if "amount_micros" in str(e) or "owner_id" in str(e) or "no such table" in str(e):
            logger.info("Self-healing: ad_ledger missing required columns, running upgrade_db...")
            upgrade_db(conn)
            row = conn.execute('''
                SELECT 
                    COALESCE(SUM(amount_micros), 0) AS total_micros,
                    COALESCE(SUM(CASE WHEN amount_micros > 0 THEN amount_micros ELSE 0 END), 0) AS network_micros,
                    COALESCE(SUM(CASE WHEN amount_micros < 0 THEN ABS(amount_micros) ELSE 0 END), 0) AS custom_micros
                FROM ad_ledger
                WHERE owner_id = ?
            ''', (uid,)).fetchone()
        else:
            raise

    total_micros = row['total_micros']
    network_micros = row['network_micros']
    custom_micros = row['custom_micros']

    earnings_dollars = total_micros / 1_000_000.0
    network_dollars = network_micros / 1_000_000.0
    custom_dollars = custom_micros / 1_000_000.0

    return {
        'earnings': round(earnings_dollars, 2),
        'earnings_formatted': f"{earnings_dollars:.2f}",
        'network_earnings': round(network_dollars, 2),
        'custom_spend': round(custom_dollars, 2),
        'total_micros': total_micros
    }

def upgrade_db(db_conn):
    """
    Executes transaction-safe, idempotent database migrations.
    Fails loudly and re-raises on unexpected database errors to prevent corrupt states.
    """
    try:
        existing_tables = {row[0] for row in db_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

        # 1. Ensure links columns exist
        if "links" in existing_tables:
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
                    logger.info("Migrated schema: added column %s to links", col_name)

        # 2. Ensure users columns exist (session_version, email, email_normalized, email_verified_at)
        if "users" in existing_tables:
            user_cursor = db_conn.execute("PRAGMA table_info(users)")
            user_cols = {row[1] for row in user_cursor.fetchall()}
            user_new_cols = [
                ("session_version", "INTEGER NOT NULL DEFAULT 1"),
                ("email", "TEXT"),
                ("email_normalized", "TEXT"),
                ("email_verified_at", "TIMESTAMP")
            ]
            for col_name, col_def in user_new_cols:
                if col_name not in user_cols:
                    db_conn.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def};")
                    logger.info("Migrated schema: added column %s to users", col_name)

            # Unique index on email_normalized
            db_conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_norm ON users(email_normalized) WHERE email_normalized IS NOT NULL;")

        # 3. Migrate ad_ledger to use micro-dollars (amount_micros), owner_id, link_code, and ON DELETE SET NULL
        if "ad_ledger" in existing_tables:
            ledger_cursor = db_conn.execute("PRAGMA table_info(ad_ledger)")
            ledger_cols = {row[1] for row in ledger_cursor.fetchall()}

            if "amount_micros" not in ledger_cols:
                logger.info("Migrating ad_ledger to amount_micros and owner-retained history...")
                db_conn.execute("PRAGMA foreign_keys = OFF;")
                db_conn.execute('''
                    CREATE TABLE IF NOT EXISTS ad_ledger_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        link_id INTEGER,
                        owner_id INTEGER,
                        link_code TEXT,
                        amount_micros INTEGER NOT NULL,
                        ip_hash TEXT DEFAULT '',
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(link_id) REFERENCES links(id) ON DELETE SET NULL,
                        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL
                    );
                ''')

                # Check if old table has data to copy over
                if "amount" in ledger_cols:
                    ip_hash_select = "COALESCE(al.ip_hash, '')" if "ip_hash" in ledger_cols else "''"
                    db_conn.execute(f'''
                        INSERT INTO ad_ledger_new (id, link_id, owner_id, link_code, amount_micros, ip_hash, timestamp)
                        SELECT 
                            al.id,
                            al.link_id,
                            l.owner_id,
                            l.code,
                            CAST(ROUND(al.amount * 1000000) AS INTEGER),
                            {ip_hash_select},
                            al.timestamp
                        FROM ad_ledger al
                        LEFT JOIN links l ON l.id = al.link_id;
                    ''')
                db_conn.execute("DROP TABLE IF EXISTS ad_ledger;")
                db_conn.execute("ALTER TABLE ad_ledger_new RENAME TO ad_ledger;")
                db_conn.execute("PRAGMA foreign_keys = ON;")
                logger.info("Successfully migrated ad_ledger to micro-dollars schema.")
            elif "owner_id" not in ledger_cols:
                db_conn.execute("ALTER TABLE ad_ledger ADD COLUMN owner_id INTEGER;")
                db_conn.execute("ALTER TABLE ad_ledger ADD COLUMN link_code TEXT;")


        # 4. Ensure rate_limits table exists
        db_conn.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                timestamp REAL NOT NULL
            );
        ''')

        # 5. Case-insensitive username unique index (wrapped safely per Refinement 11)
        if "users" in existing_tables:
            try:
                db_conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE);")
            except (sqlite3.IntegrityError, sqlite3.OperationalError) as e:
                logger.warning("Username collision or error detected during case-insensitive index creation (%s); skipping unique nocase index.", e)

        # 6. Ensure email_otps and mail_counters tables exist
        db_conn.execute('''
            CREATE TABLE IF NOT EXISTS email_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_normalized TEXT NOT NULL,
                email_display TEXT NOT NULL,
                purpose TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                user_id INTEGER,
                pending_payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                consumed_at TIMESTAMP,
                ip_hash TEXT
            );
        ''')
        db_conn.execute("CREATE INDEX IF NOT EXISTS idx_email_otps_lookup ON email_otps(email_normalized, purpose, created_at);")

        db_conn.execute('''
            CREATE TABLE IF NOT EXISTS mail_counters (
                bucket TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );
        ''')

        # 6. Performance indexes
        indexes = [
            ("idx_clicks_link_id", "CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id);"),
            ("idx_clicks_ip_hash", "CREATE INDEX IF NOT EXISTS idx_clicks_ip_hash ON clicks(ip_hash);"),
            ("idx_clicks_composite", "CREATE INDEX IF NOT EXISTS idx_clicks_composite ON clicks(link_id, ip_hash, timestamp);"),
            ("idx_links_owner_id", "CREATE INDEX IF NOT EXISTS idx_links_owner_id ON links(owner_id);"),
            ("idx_ad_ledger_link_id", "CREATE INDEX IF NOT EXISTS idx_ad_ledger_link_id ON ad_ledger(link_id);"),
            ("idx_ad_ledger_owner_id", "CREATE INDEX IF NOT EXISTS idx_ad_ledger_owner_id ON ad_ledger(owner_id);"),
            ("idx_ad_nonces_created", "CREATE INDEX IF NOT EXISTS idx_ad_nonces_created ON ad_nonces(created_at);"),
            ("idx_rate_limits_key_ts", "CREATE INDEX IF NOT EXISTS idx_rate_limits_key_ts ON rate_limits(key, timestamp);")
        ]
        for idx_name, idx_sql in indexes:
            try:
                table_name = idx_sql.split('ON ')[1].split('(')[0].strip()
                t_row = db_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)).fetchone()
                if t_row:
                    db_conn.execute(idx_sql)
            except Exception as e:
                logger.debug("Skipping index %s (table not yet created): %s", idx_name, e)

        # Drop redundant idx_links_code if present
        db_conn.execute("DROP INDEX IF EXISTS idx_links_code;")

        db_conn.commit()
    except Exception as e:
        logger.error("Critical database migration error: %s", e)
        db_conn.rollback()
        raise

def init_db(app=None):
    """
    Initializes database schema, configures journal mode, and runs migrations.
    If RESET_DB=true is set in environment, existing database files are purged first.
    """
    # Check for RESET_DB environment variable trigger
    if os.environ.get('RESET_DB', '').lower() in ('1', 'true', 'yes'):
        logger.warning("RESET_DB requested: deleting existing database files at %s...", DATABASE)
        for ext in ('', '-wal', '-shm'):
            target = f"{DATABASE}{ext}"
            if os.path.exists(target):
                try:
                    os.remove(target)
                    logger.info("Deleted database file: %s", target)
                except Exception as e:
                    logger.warning("Could not delete %s: %s", target, e)

    journal_mode = os.environ.get('DB_JOURNAL_MODE', 'WAL').upper()
    if journal_mode not in ('WAL', 'DELETE', 'TRUNCATE', 'MEMORY'):
        journal_mode = 'WAL'

    # Warn if WAL mode is used on Azure /home network-mounted filesystem
    if DATA_DIR.startswith('/home') and journal_mode == 'WAL':
        logger.warning(
            "DATA_DIR (%s) is on Azure /home network storage. SQLite WAL mode on network shares "
            "carries risk of lock contention. Consider setting DB_JOURNAL_MODE=DELETE or migrating "
            "to managed PostgreSQL.", DATA_DIR
        )

    conn = sqlite3.connect(DATABASE, timeout=DB_TIMEOUT)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute(f"PRAGMA journal_mode = {journal_mode};")

    # 1. Run migrations first on any existing legacy tables
    upgrade_db(conn)

    # 2. Run schema.sql to ensure all base tables and indexes exist
    with open(os.path.join(BASE_DIR, 'schema.sql'), 'r') as f:
        conn.executescript(f.read())

    # 3. Finalize any indexes or post-schema migration adjustments
    upgrade_db(conn)
    conn.close()


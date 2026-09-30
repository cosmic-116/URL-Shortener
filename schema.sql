PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE COLLATE NOCASE NOT NULL,
    password_hash TEXT NOT NULL,
    api_key_hash TEXT UNIQUE NOT NULL,
    email TEXT,
    email_normalized TEXT,
    email_verified_at TIMESTAMP,
    session_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Links table
CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE,
    original_url TEXT NOT NULL,
    owner_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    ads_enabled BOOLEAN DEFAULT 0,
    ad_type TEXT DEFAULT 'network', -- 'network', 'custom'
    custom_ad_url TEXT DEFAULT '',
    custom_ad_title TEXT DEFAULT '',
    custom_ad_desc TEXT DEFAULT '',
    custom_ad_media_type TEXT DEFAULT 'webpage', -- 'webpage', 'video'
    safety_status TEXT DEFAULT 'pending', -- 'pending', 'clean', 'malicious', 'unchecked'
    safety_checked_at TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Clicks table
CREATE TABLE IF NOT EXISTS clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id INTEGER NOT NULL,
    ip_hash TEXT NOT NULL,
    referrer TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(link_id) REFERENCES links(id) ON DELETE CASCADE
);

-- Ad Ledger (amount in integer micro-dollars; 1 dollar = 1,000,000 micros)
CREATE TABLE IF NOT EXISTS ad_ledger (
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

-- Ad Nonces (For token replay prevention)
CREATE TABLE IF NOT EXISTS ad_nonces (
    nonce TEXT PRIMARY KEY,
    link_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    consumed_at TIMESTAMP,
    FOREIGN KEY(link_id) REFERENCES links(id) ON DELETE CASCADE
);

-- Persistent Rate Limits Table (shared across worker processes)
CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    timestamp REAL NOT NULL
);

-- Email OTPs Table
CREATE TABLE IF NOT EXISTS email_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_normalized TEXT NOT NULL,
    email_display TEXT NOT NULL,
    purpose TEXT NOT NULL,            -- 'register' | 'reset' | 'add_email' | 'change_email'
    code_hash TEXT NOT NULL,
    user_id INTEGER,
    pending_payload TEXT,             -- register only: JSON {"username":..., "password_hash":...}
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed_at TIMESTAMP,
    ip_hash TEXT
);

-- Persistent Mail Counters Table
CREATE TABLE IF NOT EXISTS mail_counters (
    bucket TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_clicks_ip_hash ON clicks(ip_hash);
CREATE INDEX IF NOT EXISTS idx_clicks_composite ON clicks(link_id, ip_hash, timestamp);
CREATE INDEX IF NOT EXISTS idx_links_owner_id ON links(owner_id);
CREATE INDEX IF NOT EXISTS idx_ad_ledger_link_id ON ad_ledger(link_id);
CREATE INDEX IF NOT EXISTS idx_ad_nonces_created ON ad_nonces(created_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_key_ts ON rate_limits(key, timestamp);
CREATE INDEX IF NOT EXISTS idx_email_otps_lookup ON email_otps(email_normalized, purpose, created_at);


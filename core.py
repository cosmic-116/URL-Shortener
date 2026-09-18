import string
import time
import re
import ipaddress
import secrets
import hashlib
import hmac
import threading
from collections import deque
from threading import Lock
from urllib.parse import urlparse
from datetime import datetime, timezone

BASE62_ALPHABET = string.digits + string.ascii_lowercase + string.ascii_uppercase
RESERVED_ALIASES = {"shorten", "stats", "analytics", "login", "register", "logout", "static", "api", "dashboard", "continue", "qr"}

# --- Base62 & Alias Logic ---

def encode_base62(num):
    """Encodes a given non-negative integer to a Base62 string."""
    if not isinstance(num, int):
        raise TypeError("Number must be an integer")
    if num < 0:
        raise ValueError("Number must be non-negative")
    if num == 0:
        return BASE62_ALPHABET[0]
        
    base62 = []
    while num:
        num, rem = divmod(num, 62)
        base62.append(BASE62_ALPHABET[rem])
    return ''.join(reversed(base62))

def generate_short_code(conn, length=7):
    """
    Generates a cryptographically random Base62 short code.
    7 chars = 62^7 ≈ 3.5 trillion possibilities — effectively collision-free
    and completely unpredictable (no sequential enumeration).
    Retries automatically on the rare chance of a collision.
    """
    for _ in range(10):
        code = ''.join(secrets.choice(BASE62_ALPHABET) for _ in range(length))
        if is_code_available(conn, code):
            return code
    raise RuntimeError("Failed to generate a unique code after 10 attempts")

def validate_alias(alias):
    """
    Validates a custom alias. 
    Returns (True, normalized_alias) or (False, error_message).
    """
    if not isinstance(alias, str):
        return False, "Alias must be a string"
    if len(alias) < 3 or len(alias) > 30:
        return False, "Alias must be between 3 and 30 characters"
    if not re.fullmatch(r"^[A-Za-z0-9_-]+$", alias):
        return False, "Alias contains invalid characters. Use only letters, numbers, hyphens, and underscores."
        
    alias_lower = alias.lower()
    if alias_lower in RESERVED_ALIASES:
        return False, "This alias is reserved for system use."
        
    return True, alias_lower

def is_code_available(conn, code):
    """Checks if a code is already taken in the database."""
    row = conn.execute('SELECT id FROM links WHERE code = ?', (code,)).fetchone()
    return row is None

# --- Rate Limiting ---

_rate_limits = {}
_rl_lock = Lock()

def is_rate_limited(ip, max_requests=10, window_seconds=60):
    """
    Thread-safe sliding window rate limiter.
    Note: Operates in-memory for a single process.
    """
    now = time.time()
    with _rl_lock:
        if ip not in _rate_limits:
            _rate_limits[ip] = deque()
            
        dq = _rate_limits[ip]
        # Remove expired timestamps
        while dq and now - dq[0] >= window_seconds:
            dq.popleft()
            
        if len(dq) >= max_requests:
            return True
            
        dq.append(now)
        return False

# --- URL Validation & SSRF Guard ---

def is_safe_url(url):
    """
    SSRF protection and scheme validation.
    Checks hostname against private, loopback, and link-local IP blocks.
    Note: Does not mitigate DNS rebinding attacks on hostname resolution.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
            
        hostname = parsed.hostname
        if not hostname:
            return False
            
        try:
            # Check if it's an IP literal (IPv4 or IPv6)
            ip = ipaddress.ip_address(hostname)
            if (ip.is_private or ip.is_loopback or 
                ip.is_link_local or ip.is_unspecified or ip.is_reserved):
                return False
        except ValueError:
            # Not an IP literal; passes basic SSRF filter. 
            pass
            
        return True
    except Exception:
        return False

# --- API Key Management ---

def generate_api_key():
    """Generates a secure, random API key and its hash."""
    plaintext_key = secrets.token_urlsafe(32)
    return plaintext_key, hash_api_key(plaintext_key)

def hash_api_key(key):
    """Hashes the API key using SHA-256 for database storage."""
    return hashlib.sha256(key.encode()).hexdigest()

def verify_api_key(plaintext_key, stored_hash):
    """Safely compares an incoming API key against a stored hash."""
    expected_hash = hash_api_key(plaintext_key)
    return hmac.compare_digest(expected_hash, stored_hash)

# --- Malicious Link Checking ---

def heuristic_check(url):
    """
    Performs a synchronous heuristic check. 
    Returns a list of flags. Empty list means no immediate problems found.
    """
    flags = []
    suspicious_keywords = ['malicious', 'evil', 'hack', 'phishing', 'virus']
    url_lower = url.lower()
    
    if any(word in url_lower for word in suspicious_keywords):
        flags.append("Suspicious keyword found in URL")
        
    try:
        hostname = urlparse(url).hostname
        if hostname:
            ipaddress.ip_address(hostname)
            flags.append("URL uses an IP literal instead of a domain")
    except ValueError:
        pass
        
    return flags

def _external_check_worker(app, link_id, url):
    """Background worker to simulate calling an external safety API."""
    with app.app_context():
        import db
        time.sleep(2) # Simulate network delay
        
        # Mock external verdict
        is_safe = "super-evil" not in url.lower()
        new_status = "clean" if is_safe else "malicious"
        
        conn = db.get_db()
        conn.execute(
            'UPDATE links SET safety_status = ?, safety_checked_at = ? WHERE id = ?',
            (new_status, datetime.now(timezone.utc).isoformat(), link_id)
        )
        conn.commit()

def queue_external_check(app, link_id, url):
    """Dispatches the external safety check to a background thread."""
    t = threading.Thread(target=_external_check_worker, args=(app, link_id, url))
    t.start()

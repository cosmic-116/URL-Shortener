import os
import time
import string
import re
import socket
import ipaddress
import secrets
import hashlib
import hmac
import logging
import tempfile
import concurrent.futures
from collections import deque
from threading import BoundedSemaphore, Lock
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("snip.core")

BASE62_ALPHABET = string.digits + string.ascii_lowercase + string.ascii_uppercase
RESERVED_ALIASES = {
    "shorten", "stats", "analytics", "login", "register", "logout",
    "static", "api", "dashboard", "continue", "qr", "health", "robots.txt",
    "preview", "robots", "favicon", "admin", "status", "terms", "privacy",
    "docs", "help", "about", "contact", "settings"
}

# INSECURE default used only for local development / automated tests
DEFAULT_API_PEPPER = "snip-core-api-pepper-insecure-dev-only"

# Cloud metadata and internal blocked hostnames
BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "169.254.169.254",
    "instance-data",
    "metadata",
    "localhost"
}

ALLOWED_PORTS = {80, 443, 8080, 8443}
_NAT64_PREFIX = ipaddress.IPv6Network('64:ff9b::/96')

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bitly.com", "tiny.cc", "rb.gy"
}
SUSPICIOUS_PHISHING_WORDS = [
    "phishing", "malware", "virus", "credential", "verify-account", "signin-security"
]

# Shared thread pool for background asynchronous jobs
_MAX_QUEUE_SIZE = 100
_worker_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="snip-worker")


# ── Base62 & Short Code Helpers ─────────────────────────────

def generate_short_code(conn, length=7):
    """Generates a cryptographically random Base62 short code."""
    for _ in range(10):
        code = ''.join(secrets.choice(BASE62_ALPHABET) for _ in range(length))
        if is_code_available(conn, code):
            return code
    raise RuntimeError("Failed to generate a unique code after 10 attempts")

def validate_alias(alias):
    """Validates user-defined custom aliases."""
    if not isinstance(alias, str):
        return False, "Alias must be a string"
    alias = alias.strip()
    if len(alias) < 3 or len(alias) > 30:
        return False, "Alias must be between 3 and 30 characters"
    if not re.fullmatch(r"^[A-Za-z0-9_-]+$", alias):
        return False, "Alias contains invalid characters. Use only letters, numbers, hyphens, and underscores."

    alias_lower = alias.lower()
    if alias_lower in RESERVED_ALIASES:
        return False, "This alias is reserved for system use."

    # Return alias preserving user's typed case
    return True, alias

def is_code_available(conn, code):
    """Checks if a short code is available, checking case-insensitively for custom aliases."""
    row = conn.execute('SELECT id FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
    return row is None

def calculate_expiry(expires_in):
    """
    Parses expires_in parameter (seconds int/float, shorthand string like '24h', '7d', '60m', '3600s',
    or ISO-8601 string) and returns (is_valid, formatted_utc_timestamp_or_error_msg).
    If expires_in is None or empty, returns (True, None).
    """
    if expires_in is None:
        return True, None
    if isinstance(expires_in, bool):
        return False, "expires_in cannot be a boolean"
    if isinstance(expires_in, (int, float)):
        import math
        if not math.isfinite(expires_in):
            return False, "expires_in must be a finite number"
        seconds = float(expires_in)
    elif isinstance(expires_in, str):
        expires_in = expires_in.strip()
        if not expires_in:
            return True, None
        
        lower = expires_in.lower()
        if lower.endswith('s') and lower[:-1].isdigit():
            seconds = float(lower[:-1])
        elif lower.endswith('m') and lower[:-1].isdigit():
            seconds = float(lower[:-1]) * 60
        elif lower.endswith('h') and lower[:-1].isdigit():
            seconds = float(lower[:-1]) * 3600
        elif lower.endswith('d') and lower[:-1].isdigit():
            seconds = float(lower[:-1]) * 86400
        elif expires_in.isdigit():
            seconds = float(expires_in)
        else:
            try:
                dt = datetime.fromisoformat(expires_in.replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if dt <= now:
                    return False, "Expiration time must be in the future."
                return True, dt.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                return False, "Invalid expires_in format. Use seconds, duration (e.g. '24h', '7d'), or ISO timestamp."
    else:
        return False, "Invalid expires_in type."

    if seconds <= 0:
        return False, "Expiration duration must be greater than zero."
    if seconds > 31536000:
        return False, "Expiration duration cannot exceed 365 days."

    expiry_dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return True, expiry_dt.strftime('%Y-%m-%d %H:%M:%S')


# ── SQLite-Backed Rate Limiting Engine ───────────────────────

_rate_limits = {}
_rl_lock = Lock()

def is_rate_limited(key, max_requests=15, window_seconds=60, conn=None, record=True):
    """
    SQLite-backed sliding-window rate limiter sharing state across Gunicorn workers.
    Falls back gracefully to in-memory deque if database is unavailable.
    """
    if not key:
        return False
    now = time.time()
    cutoff = now - window_seconds

    try:
        import db
        if conn is None:
            conn = db.get_db()

        # Prune stale records for this namespace
        conn.execute('DELETE FROM rate_limits WHERE key = ? AND timestamp < ?', (key, cutoff))
        count_row = conn.execute(
            'SELECT COUNT(*) as cnt FROM rate_limits WHERE key = ? AND timestamp >= ?',
            (key, cutoff)
        ).fetchone()
        count = count_row['cnt'] if count_row else 0

        if count >= max_requests:
            return True

        if record:
            conn.execute('INSERT INTO rate_limits (key, timestamp) VALUES (?, ?)', (key, now))
            conn.commit()
        return False
    except Exception as e:
        logger.debug("Database rate limiter fallback: %s", e)
        with _rl_lock:
            if len(_rate_limits) > 5000:
                stale_keys = [k for k, dq in _rate_limits.items() if not dq or now - dq[-1] >= window_seconds]
                for k in stale_keys:
                    del _rate_limits[k]

            if key not in _rate_limits:
                _rate_limits[key] = deque()

            dq = _rate_limits[key]
            while dq and now - dq[0] >= window_seconds:
                dq.popleft()

            if len(dq) >= max_requests:
                return True

            if record:
                dq.append(now)
            return False


# ── SSRF Guard & DNS Hardening ──────────────────────────────

_dns_cache = {}
_dns_cache_lock = Lock()
_DNS_CACHE_TTL = 300.0  # 5 minutes
_DNS_CACHE_MAX_SIZE = 512
_dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="snip-dns")
_dns_slots = BoundedSemaphore(32)

def _get_cached_verdict(hostname):
    now = time.time()
    with _dns_cache_lock:
        if hostname in _dns_cache:
            verdict, ts = _dns_cache[hostname]
            if now - ts < _DNS_CACHE_TTL:
                return verdict
            del _dns_cache[hostname]
    return None

def _set_cached_verdict(hostname, verdict):
    now = time.time()
    with _dns_cache_lock:
        if len(_dns_cache) >= _DNS_CACHE_MAX_SIZE:
            oldest = min(_dns_cache.keys(), key=lambda k: _dns_cache[k][1])
            del _dns_cache[oldest]
        _dns_cache[hostname] = (verdict, now)

def is_safe_ip(ip_obj):
    """
    Enforces ip.is_global to block private, loopback, link-local,
    CGNAT (100.64.0.0/10), multicast, and reserved ranges.
    Unwraps IPv4-mapped IPv6, 6to4, and NAT64 embedded addresses.
    """
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        elif ip_obj.sixtofour:
            ip_obj = ip_obj.sixtofour
        else:
            if ip_obj in _NAT64_PREFIX:
                ip_obj = ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)

    return ip_obj.is_global

def _parse_and_normalize_url(url):
    """
    Syntactically validates, normalizes, and sanitizes input URL.
    Returns (ok, error_msg, parsed_url, normalized_hostname).
    """
    if not isinstance(url, str):
        return False, "URL must be a string", None, None
    url = url.strip()
    if not url or len(url) > 2048:
        return False, "URL is missing or exceeds 2048 characters", None, None

    # Reject backslashes, whitespace, and control characters
    if '\\' in url or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        return False, "URL contains disallowed whitespace or control characters", None, None

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL parsing failed", None, None

    if parsed.scheme.lower() not in ('http', 'https'):
        return False, "Only HTTP and HTTPS schemes are supported", None, None

    if parsed.username or parsed.password or '@' in (parsed.netloc or ''):
        return False, "Userinfo (user:pass@) is forbidden", None, None

    try:
        port = parsed.port
    except ValueError:
        return False, "Destination URL contains an invalid port", None, None
    if port is not None and port not in ALLOWED_PORTS:
        return False, f"Port {port} is not permitted", None, None

    hostname = parsed.hostname
    if not hostname:
        return False, "Destination URL is missing a hostname", None, None

    hostname_clean = hostname.rstrip('.').lower()

    try:
        hostname_clean = hostname_clean.encode('idna').decode('ascii')
    except UnicodeError:
        return False, "Hostname IDNA encoding failed", None, None

    if hostname_clean in BLOCKED_HOSTNAMES or hostname_clean.endswith(".internal"):
        return False, "Destination points to internal or blocked host", None, None

    return True, "", parsed, hostname_clean

def _resolve_dns_with_timeout(hostname, timeout=3.0):
    """Resolve DNS without allowing a stalled resolver to block the request thread."""
    if not _dns_slots.acquire(blocking=False):
        raise TimeoutError("DNS resolver capacity is temporarily exhausted")

    def _do_resolve():
        try:
            return socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except Exception as e:
            return e

    try:
        fut = _dns_executor.submit(_do_resolve)
    except Exception:
        _dns_slots.release()
        raise
    fut.add_done_callback(lambda _future: _dns_slots.release())
    try:
        res = fut.result(timeout=timeout)
    except concurrent.futures.TimeoutError as exc:
        raise TimeoutError(f"DNS resolution timed out after {timeout}s") from exc
    if isinstance(res, Exception):
        raise res
    return res

def validate_url_at_creation(url):
    """
    Strict URL validation for creation time. Actively performs DNS resolution
    with a 3s timeout and ensures all returned IP addresses are public/global.
    """
    ok, err, parsed, hostname_clean = _parse_and_normalize_url(url)
    if not ok:
        return False

    cached = _get_cached_verdict(hostname_clean)
    if cached is not None:
        return cached

    # Check if decimal IP literal or standard IP literal
    if hostname_clean.isdigit():
        try:
            ip = ipaddress.ip_address(int(hostname_clean))
            return is_safe_ip(ip)
        except ValueError:
            return False

    try:
        ip = ipaddress.ip_address(hostname_clean)
        return is_safe_ip(ip)
    except ValueError:
        pass

    # Resolve via DNS with strict timeout
    try:
        addr_info = _resolve_dns_with_timeout(hostname_clean, timeout=3.0)
        if not addr_info:
            return False

        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if not is_safe_ip(ip_obj):
                logger.warning("SSRF blocked: %s resolved to non-global IP %s", hostname_clean, ip_str)
                _set_cached_verdict(hostname_clean, False)
                return False

        _set_cached_verdict(hostname_clean, True)
        return True
    except Exception as e:
        logger.debug("DNS resolution failed or timed out for %s: %s", hostname_clean, e)
        return False

def validate_url_at_redirect(url):
    """
    Fast, cached URL verification for redirect routes (/<code> and /continue).
    Uses a 5-minute bounded LRU verdict cache to prevent slow DNS from blocking workers.
    """
    ok, err, parsed, hostname_clean = _parse_and_normalize_url(url)
    if not ok:
        return False

    # IP literal check
    if hostname_clean.isdigit():
        try:
            ip = ipaddress.ip_address(int(hostname_clean))
            return is_safe_ip(ip)
        except ValueError:
            return False

    try:
        ip = ipaddress.ip_address(hostname_clean)
        return is_safe_ip(ip)
    except ValueError:
        pass

    cached = _get_cached_verdict(hostname_clean)
    if cached is not None:
        return cached

    # Attempt quick resolution if not in cache
    try:
        addr_info = _resolve_dns_with_timeout(hostname_clean, timeout=3.0)
        for item in addr_info:
            sockaddr = item[4]
            ip_obj = ipaddress.ip_address(sockaddr[0])
            if not is_safe_ip(ip_obj):
                _set_cached_verdict(hostname_clean, False)
                return False
        _set_cached_verdict(hostname_clean, True)
        return True
    except Exception:
        # If DNS fails at redirect time, do not permanently fail if previously valid
        return False

def is_safe_url(url):
    """Backward-compatible alias for URL validation at creation."""
    return validate_url_at_creation(url)


# ── User & Auth Validation ──────────────────────────────────

def validate_username(username):
    """Validates user account username length and character set."""
    if not isinstance(username, str):
        return False, "Username must be a string."
    username = username.strip()
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not re.fullmatch(r"^[A-Za-z0-9_-]+$", username):
        return False, "Username can only contain letters, numbers, hyphens, and underscores."
    return True, username

def validate_password(password):
    """Validates password strength (min 8 chars, max 128, mixed letters and numbers)."""
    if not isinstance(password, str):
        return False, "Password must be a string."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not any(c.isalpha() for c in password):
        return False, "Password must include at least one letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must include at least one number."
    return True, ""

_disposable_domains = None
_disposable_domains_lock = Lock()

def get_disposable_domains():
    """Loads and caches the set of disposable/temporary email provider domains."""
    global _disposable_domains
    with _disposable_domains_lock:
        if _disposable_domains is None:
            domains = set()
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'disposable_domains.txt')
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip().lower()
                            if line and not line.startswith('#'):
                                domains.add(line)
                except Exception as e:
                    logger.warning("Failed to load disposable domains: %s", e)
            _disposable_domains = domains
        return _disposable_domains

def validate_email(email):
    """
    Validates, normalizes, and sanitizes an email address according to RFC and Snip security rules.
    Returns (ok: bool, normalized_or_error: str).
    """
    if not isinstance(email, str):
        return False, "Email must be a string."
    
    email = email.strip()
    if not email:
        return False, "Email address is required."
    
    if len(email) > 254:
        return False, "Email address exceeds maximum length of 254 characters."
    
    # Reject whitespace, control characters, commas, semicolons, angle brackets, quotes, CR, LF
    if any(c in email for c in ['\r', '\n', ' ', '\t', ',', ';', '<', '>', '"', "'"]):
        return False, "Email contains invalid characters or line breaks."
    
    if any(ord(c) < 32 or ord(c) == 127 for c in email):
        return False, "Email contains disallowed control characters."
    
    parts = email.split('@')
    if len(parts) != 2:
        return False, "Email must contain exactly one '@' symbol."
    
    local, domain = parts
    if not local or len(local) > 64:
        return False, "Local part must be between 1 and 64 characters."
    
    if not domain or '.' not in domain or domain.startswith('.') or domain.endswith('.'):
        return False, "Domain must contain a valid top-level domain."
    
    # Validate domain with IDNA punycode
    try:
        domain_ascii = domain.encode('idna').decode('ascii').lower()
    except (UnicodeError, UnicodeDecodeError):
        return False, "Domain contains invalid internationalized characters."
    
    # Ensure domain components are valid
    labels = domain_ascii.split('.')
    if any(not l or l.startswith('-') or l.endswith('-') for l in labels):
        return False, "Domain contains malformed labels."
    
    domain_norm = domain_ascii
    local_norm = local.lower()
    
    # Disposable domain checking
    block_disposable = os.environ.get('BLOCK_DISPOSABLE_EMAILS', '1') in ('1', 'true', 'True')
    if block_disposable:
        disposable_set = get_disposable_domains()
        if domain_norm in disposable_set or any(domain_norm.endswith('.' + d) for d in disposable_set):
            return False, "Disposable email addresses are not permitted."
    
    # Provider-specific normalization
    if domain_norm in ('gmail.com', 'googlemail.com'):
        domain_norm = 'gmail.com'
        # Strip +tag and all dots
        local_norm = local_norm.split('+', 1)[0]
        local_norm = local_norm.replace('.', '')
    elif domain_norm in ('icloud.com', 'me.com', 'mac.com'):
        # Strip +tag
        local_norm = local_norm.split('+', 1)[0]
    
    if not local_norm:
        return False, "Email local part cannot be empty after normalization."
    
    email_normalized = f"{local_norm}@{domain_norm}"
    return True, email_normalized

def normalize_email(email):
    """Convenience helper to extract normalized email string, or None if invalid."""
    ok, res = validate_email(email)
    return res if ok else None

def extract_youtube_embed(url):
    """Safely extracts a YouTube video ID and returns privacy-enhanced embed URL."""
    if not isinstance(url, str):
        return None
    url = url.strip()
    m = re.search(r'(?:youtube\.com\/(?:watch\?.*v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})', url)
    if m:
        video_id = m.group(1)
        return f"https://www.youtube-nocookie.com/embed/{video_id}"
    return None


# ── API Key Management ──────────────────────────────────────

def get_api_pepper():
    """Retrieves system pepper for API keys. Fails fast in production if unset."""
    pepper = os.environ.get('API_KEY_PEPPER')
    is_debug = os.environ.get('FLASK_DEBUG') == '1' or os.environ.get('FLASK_ENV') == 'development'
    is_testing = os.environ.get('TESTING') == '1'
    if not pepper:
        if not is_debug and not is_testing:
            raise RuntimeError("API_KEY_PEPPER environment variable must be set in production.")
        return DEFAULT_API_PEPPER
    return pepper

def generate_api_key():
    """Generates a secure random API key and its salted hash."""
    plaintext_key = secrets.token_urlsafe(32)
    return plaintext_key, hash_api_key(plaintext_key)

def hash_api_key(key, pepper=None):
    """Hashes the API key using HMAC-SHA256 with the system pepper."""
    p = (pepper or get_api_pepper()).encode('utf-8')
    return hmac.new(p, key.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_api_key(plaintext_key, stored_hash, pepper=None):
    """Compares plaintext key against stored hash using constant-time comparison."""
    p = pepper or get_api_pepper()
    expected_hash = hash_api_key(plaintext_key, p)
    if hmac.compare_digest(expected_hash, stored_hash):
        return True

    # Backward compatibility with legacy unsalted SHA-256
    allow_legacy = os.environ.get('ALLOW_LEGACY_API_KEYS', '1') == '1'
    if allow_legacy:
        legacy_hash = hashlib.sha256(plaintext_key.encode('utf-8')).hexdigest()
        return hmac.compare_digest(legacy_hash, stored_hash)
    return False

def get_user_by_api_key(conn, api_key):
    """Single-query user authentication by API key with constant-time verification."""
    if not api_key or not isinstance(api_key, str):
        return None
    pepper = get_api_pepper()
    curr_hash = hash_api_key(api_key, pepper)
    allow_legacy = os.environ.get('ALLOW_LEGACY_API_KEYS', '1') == '1'

    if allow_legacy:
        legacy_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
        rows = conn.execute(
            'SELECT * FROM users WHERE api_key_hash IN (?, ?)',
            (curr_hash, legacy_hash)
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT * FROM users WHERE api_key_hash = ?',
            (curr_hash,)
        ).fetchall()

    for user in rows:
        if verify_api_key(api_key, user['api_key_hash'], pepper):
            return user
    return None


# ── Threat & Safety Inspection ──────────────────────────────

def heuristic_check(url):
    """Performs synchronous heuristic threat evaluation on hostname and path."""
    flags = []
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or '').lower()
        path = (parsed.path or '').lower()
        host_and_path = f"{hostname}{path}"

        # 1. IP-literal hosts
        try:
            ipaddress.ip_address(hostname)
            flags.append("URL uses an IP literal instead of a domain")
        except ValueError:
            pass

        # 2. Punycode / IDN homograph encoding
        if "xn--" in hostname:
            flags.append("URL uses punycode/IDN homograph encoding")

        # 3. Excessive subdomain nesting
        if hostname.count('.') > 3:
            flags.append("Excessive subdomain nesting detected")

        # 4. Known URL shortener chains
        if any(hostname == s or hostname.endswith("." + s) for s in SHORTENER_DOMAINS):
            flags.append("Redirect chain: points to another URL shortener")

        # 5. Phishing / malware keywords
        if any(kw in host_and_path for kw in SUSPICIOUS_PHISHING_WORDS):
            flags.append("Suspicious security or phishing keyword in hostname/path")

        # 6. 'hack' or 'evil' only when combined with other indicators
        if any(kw in host_and_path for kw in ['hack', 'evil']) and flags:
            flags.append("Suspicious keyword combined with anomaly")
    except Exception as e:
        logger.debug("Heuristic check error: %s", e)

    return flags

def _external_check_worker(app, link_id, url):
    """Worker task that checks safety with Google Safe Browsing or sets unchecked status."""
    with app.app_context():
        import db
        import requests

        flags = heuristic_check(url)
        api_key = os.environ.get('SAFE_BROWSING_API_KEY')

        if api_key:
            gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            payload = {
                "client": {"clientId": "snip-url-shortener", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            try:
                r = requests.post(gsb_url, json=payload, timeout=5.0)
                if r.status_code == 200 and r.json().get('matches'):
                    new_status = 'malicious'
                else:
                    new_status = 'malicious' if flags else 'clean'
            except Exception as e:
                logger.warning("Safe Browsing API check failed: %s", e)
                new_status = 'malicious' if flags else 'clean'
        else:
            # Local heuristic threat evaluation: clean if no flags, malicious if threat indicators found
            new_status = 'malicious' if flags else 'clean'

        try:
            conn = db.get_db()
            conn.execute(
                'UPDATE links SET safety_status = ?, safety_checked_at = CURRENT_TIMESTAMP WHERE id = ?',
                (new_status, link_id)
            )
            conn.commit()
        except Exception as e:
            logger.error("Failed to update safety status for link %s: %s", link_id, e)

def queue_external_check(app, link_id, url):
    """Dispatches safety checks to the bounded thread pool."""
    if os.environ.get('TESTING') == '1' or getattr(app, 'testing', False) or (hasattr(app, 'config') and app.config.get('TESTING')):
        return
    if _worker_executor._work_queue.qsize() > _MAX_QUEUE_SIZE:
        logger.warning("Worker queue full, dropping safety check for link %s", link_id)
        return
    _worker_executor.submit(_external_check_worker, app, link_id, url)


# ── Screenshot Capture Worker ───────────────────────────────

_in_progress_screenshots = set()
_screenshot_lock = Lock()

def _generate_fallback_screenshot(filepath, domain):
    try:
        from PIL import Image, ImageDraw
        img = Image.new('RGB', (800, 500), color=(22, 33, 62))
        draw = ImageDraw.Draw(img)
        draw.rectangle([(16, 16), (784, 484)], outline=(42, 42, 74), width=2)
        draw.text((400, 230), domain or 'Website Preview', fill=(234, 234, 234), anchor='mm')
        draw.text((400, 270), 'Live Snapshot Unavailable', fill=(233, 69, 96), anchor='mm')
        img.save(filepath, format='JPEG', quality=85)
    except Exception as e:
        logger.debug("Failed to generate fallback preview image: %s", e)

def _screenshot_worker(code, url, data_dir):
    """Captures website preview snapshot using Microlink API."""
    try:
        try:
            parsed = urlparse(url)
            if parsed.fragment:
                url = url.split('#', 1)[0]
        except Exception:
            return

        import requests
        screenshots_dir = os.path.join(data_dir, 'screenshots')
        os.makedirs(screenshots_dir, exist_ok=True)
        filepath = os.path.join(screenshots_dir, f"{code}.jpg")

        # Remove stale screenshot before new capture
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError:
                pass

        params = {
            'url': url,
            'screenshot': 'true',
            'meta': 'false',
            'waitFor': '5000',
            'headers[user-agent]': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        }
        captured = False
        try:
            r = requests.get("https://api.microlink.io/", params=params, timeout=25)
            if r.status_code == 200:
                data = r.json()
                screenshot_url = data.get('data', {}).get('screenshot', {}).get('url')
                if screenshot_url and is_safe_url(screenshot_url) and screenshot_url.startswith('https://'):
                    img_r = requests.get(screenshot_url, stream=True, timeout=15)
                    content_type = img_r.headers.get('Content-Type', '')
                    if img_r.status_code == 200 and content_type.startswith('image/'):
                        max_size = 5 * 1024 * 1024  # 5 MB cap
                        total_bytes = 0
                        temp_fd, temp_path = tempfile.mkstemp(dir=screenshots_dir, suffix='.tmp')
                        try:
                            with os.fdopen(temp_fd, 'wb') as f:
                                for chunk in img_r.iter_content(chunk_size=8192):
                                    total_bytes += len(chunk)
                                    if total_bytes > max_size:
                                        raise ValueError("Screenshot exceeds 5MB limit")
                                    f.write(chunk)
                            try:
                                from PIL import Image
                                with Image.open(temp_path) as im:
                                    im.convert('RGB').save(filepath, format='JPEG', quality=85, optimize=True)
                                captured = True
                            finally:
                                if os.path.exists(temp_path):
                                    os.remove(temp_path)
                        except Exception:
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                            raise
        except Exception as e:
            logger.warning("[Screenshot Error] Failed capture for %s: %s", url, e)

        if not captured and not os.path.exists(filepath):
            _generate_fallback_screenshot(filepath, parsed.netloc or code)
    finally:
        with _screenshot_lock:
            _in_progress_screenshots.discard(code)

def capture_screenshot(code, url, data_dir):
    """Submits screenshot capture to the bounded thread pool."""
    if os.environ.get('TESTING') == '1':
        return
    if os.environ.get('ENABLE_SCREENSHOTS', '1') not in ('1', 'true', 'True'):
        return
    with _screenshot_lock:
        if code in _in_progress_screenshots:
            return
        if _worker_executor._work_queue.qsize() > _MAX_QUEUE_SIZE:
            logger.warning("Worker queue full, dropping screenshot task for %s", code)
            return
        _in_progress_screenshots.add(code)
    _worker_executor.submit(_screenshot_worker, code, url, data_dir)

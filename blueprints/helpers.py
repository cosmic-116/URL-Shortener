import os
import re
import hmac
import hashlib
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from flask import request, jsonify, session, redirect, url_for, g, flash, current_app
from itsdangerous import URLSafeTimedSerializer

import db
import core

DUMMY_PW_HASH = 'scrypt:32768:8:1$dummy$dummy'

BOT_UA_PATTERNS = re.compile(
    r'(bot|crawl|spider|slurp|facebookexternalhit|whatsapp|telegrambot|twitterbot|pinterest|discordbot|curl|wget|python-requests|headless)',
    re.IGNORECASE
)

class LazySerializer:
    def __init__(self, salt):
        self.salt = salt
    def _get(self):
        return URLSafeTimedSerializer(current_app.secret_key, salt=self.salt)
    def dumps(self, *args, **kwargs):
        return self._get().dumps(*args, **kwargs)
    def loads(self, *args, **kwargs):
        return self._get().loads(*args, **kwargs)

serializer = LazySerializer(salt="snip-ad-token")
pending_serializer = LazySerializer(salt="snip-pending")

def get_ad_serializer():
    return serializer

def get_pending_serializer():
    return pending_serializer

def get_ip_hash(ip):
    """Derives an isolated key for IP hashing to protect raw secret key."""
    derived_key = hashlib.sha256(current_app.secret_key.encode('utf-8') + b"|iphash").digest()
    return hmac.new(derived_key, ip.encode('utf-8'), hashlib.sha256).hexdigest()

def build_short_url(code):
    """Builds the public short URL using BASE_URL if configured, falling back to request.host_url."""
    base = os.environ.get('BASE_URL', '').strip().rstrip('/')
    if base:
        if not base.startswith(('http://', 'https://')):
            base = 'https://' + base
        return f"{base}/{code}"
    return request.host_url + code

def get_json_payload():
    """
    Safely parses JSON payload from request. Returns (payload_dict, error_response).
    Guarantees body is a dictionary object.
    """
    if request.is_json:
        try:
            data = request.get_json(silent=True)
            if data is None or not isinstance(data, dict):
                return None, (jsonify({'error': 'Malformed or invalid JSON payload. Object expected.'}), 400)
            return data, None
        except Exception:
            return None, (jsonify({'error': 'Invalid JSON body.'}), 400)
    return None, None

def _parse_link_expiry(expires_at_str):
    """Parses link expiration string (ISO 8601 or SQLite format) to timezone-aware UTC datetime."""
    if not expires_at_str:
        return None
    s = str(expires_at_str).replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

def _delete_screenshot_file(code):
    """Safely cleans up any stored screenshot for a deleted link code."""
    screenshots_dir = os.path.join(db.DATA_DIR, 'screenshots')
    filepath = os.path.join(screenshots_dir, f"{code}.jpg")
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
        except OSError:
            pass

def _clean_ad_config(data):
    """
    Helper to sanitize, validate, and normalize ad configuration parameters.
    Always validates custom_ad_url with core.is_safe_url if non-empty,
    regardless of ads_enabled or ad_type.
    Returns (ok, cleaned_or_error_msg).
    """
    ad_type = data.get('ad_type', 'network')
    if ad_type not in ('network', 'custom'):
        ad_type = 'network'

    custom_ad_url = (data.get('custom_ad_url') or '').strip()
    custom_ad_title = (data.get('custom_ad_title') or '').strip()[:80]
    custom_ad_desc = (data.get('custom_ad_desc') or '').strip()[:200]
    custom_ad_media_type = data.get('custom_ad_media_type', 'link')
    if custom_ad_media_type not in ('link', 'video'):
        custom_ad_media_type = 'link'

    # Security check: validate custom_ad_url at creation/save time
    if custom_ad_url:
        if len(custom_ad_url) > 2048 or not core.is_safe_url(custom_ad_url):
            return False, 'Invalid or unsafe custom ad URL. Must be a public, safe HTTP/HTTPS URL.'

    if ad_type == 'custom' and not custom_ad_url:
        return False, 'Custom ad URL is required when custom ad type is selected.'

    return True, {
        'ad_type': ad_type,
        'custom_ad_url': custom_ad_url,
        'custom_ad_title': custom_ad_title,
        'custom_ad_desc': custom_ad_desc,
        'custom_ad_media_type': custom_ad_media_type
    }

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = db.get_db()
        user = conn.execute('SELECT id, session_version FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or user['session_version'] != session.get('session_version'):
            session.clear()
            flash('Your session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'Missing X-API-Key header'}), 401

        ip = request.remote_addr or 'unknown'
        if core.is_rate_limited(f"api_fail:{ip}", max_requests=10, window_seconds=600):
            return jsonify({'error': 'Too many failed API key attempts. Try again later.'}), 429

        conn = db.get_db()
        user = core.get_user_by_api_key(conn, api_key)
        if not user:
            core.is_rate_limited(f"api_fail:{ip}", max_requests=10, window_seconds=600)
            return jsonify({'error': 'Invalid API key'}), 401

        require_verified = os.environ.get('REQUIRE_VERIFIED_EMAIL_FOR_API') == '1'
        if require_verified and not user['email_verified_at']:
            return jsonify({'error': 'Email verification required to access API'}), 403

        g.api_user = user
        return f(*args, **kwargs)
    return decorated_function

def _shorten_logic(owner_id):
    ip = request.remote_addr or 'unknown'
    if core.is_rate_limited(ip):
        return jsonify({'error': 'Rate limit exceeded. Please wait a minute before creating more links.'}), 429

    if request.is_json:
        data, err_resp = get_json_payload()
        if err_resp:
            return err_resp
    else:
        data = request.form

    url = data.get('url')
    alias = data.get('alias')
    expires_in = data.get('expires_in')
    ads_enabled = data.get('ads_enabled') in ('true', 'on', '1', True)

    if not isinstance(url, str) or not url.strip():
        return jsonify({'error': 'URL is required.'}), 400

    url = url.strip()[:2048]

    if not core.validate_url_at_creation(url):
        return jsonify({'error': 'Invalid or unsafe destination URL. Only public http/https domains allowed.'}), 400

    # Parse and validate expiration duration/timestamp
    ok_exp, expiry_res = core.calculate_expiry(expires_in)
    if not ok_exp:
        return jsonify({'error': expiry_res}), 400
    expires_at = expiry_res

    conn = db.get_db()

    # 1. Alias validation
    code = None
    if alias and isinstance(alias, str) and alias.strip():
        is_valid, result = core.validate_alias(alias.strip()[:30])
        if not is_valid:
            return jsonify({'error': result}), 400
        code = result
        if not core.is_code_available(conn, code):
            return jsonify({'error': 'Alias already in use. Choose another.'}), 409

    heuristic_flags = core.heuristic_check(url)
    initial_safety = 'pending'

    # Ad configuration: only authenticated and email-verified link owners may enable ads
    owner = conn.execute('SELECT email_verified_at FROM users WHERE id = ?', (owner_id,)).fetchone() if owner_id else None
    if owner and owner['email_verified_at']:
        ok, ad_cfg = _clean_ad_config(data)
        if not ok:
            return jsonify({'error': ad_cfg}), 400
        ad_type = ad_cfg['ad_type']
        custom_ad_url = ad_cfg['custom_ad_url']
        custom_ad_title = ad_cfg['custom_ad_title']
        custom_ad_desc = ad_cfg['custom_ad_desc']
        custom_ad_media_type = ad_cfg['custom_ad_media_type']
    else:
        ads_enabled = False
        ad_type = 'network'
        custom_ad_url = ''
        custom_ad_title = ''
        custom_ad_desc = ''
        custom_ad_media_type = 'link'

    cur = conn.cursor()
    link_id = None

    if code:
        # User-provided custom alias
        try:
            cur.execute('''
                INSERT INTO links (code, original_url, owner_id, expires_at, ads_enabled, safety_status, ad_type, custom_ad_url, custom_ad_title, custom_ad_desc, custom_ad_media_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (code, url, owner_id, expires_at, ads_enabled, initial_safety, ad_type, custom_ad_url, custom_ad_title, custom_ad_desc, custom_ad_media_type))
            link_id = cur.lastrowid
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({'error': 'Alias already in use. Choose another.'}), 409
    else:
        # Random code generation with retry loop to handle collisions cleanly
        for _ in range(5):
            candidate_code = core.generate_short_code(conn)
            try:
                cur.execute('''
                    INSERT INTO links (code, original_url, owner_id, expires_at, ads_enabled, safety_status, ad_type, custom_ad_url, custom_ad_title, custom_ad_desc, custom_ad_media_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (candidate_code, url, owner_id, expires_at, ads_enabled, initial_safety, ad_type, custom_ad_url, custom_ad_title, custom_ad_desc, custom_ad_media_type))
                link_id = cur.lastrowid
                conn.commit()
                code = candidate_code
                break
            except sqlite3.IntegrityError:
                conn.rollback()
                continue

        if not link_id:
            return jsonify({'error': 'Code collision. Please try again.'}), 409

    # Background checks
    core.queue_external_check(current_app._get_current_object(), link_id, url)
    core.capture_screenshot(code, url, db.DATA_DIR)

    short_url = build_short_url(code)
    return jsonify({
        'code': code,
        'short_url': short_url,
        'original_url': url,
        'expires_at': expires_at,
        'heuristic_flags': heuristic_flags
    })

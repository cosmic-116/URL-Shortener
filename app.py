import os
import io
import re
import time
import json
import hashlib
import hmac
import secrets
import logging
import threading
import math
from datetime import datetime, timezone, timedelta
from functools import wraps
import sqlite3

import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers.pil import RoundedModuleDrawer
from qrcode.image.styles.colormasks import RadialGradiantColorMask

from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, session, g, abort, flash, send_from_directory,
                   make_response)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

import db
import core
import mailer
import otp
from mailer import MailStatus

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("snip.app")

app = Flask(__name__)

# Enforce FLASK_SECRET_KEY in production
_secret = os.environ.get('FLASK_SECRET_KEY')
_is_debug = os.environ.get('FLASK_DEBUG') == '1' or os.environ.get('FLASK_ENV') == 'development'
_is_testing = app.config.get('TESTING', False) or os.environ.get('TESTING') == '1'

if not _secret:
    if not _is_debug and not _is_testing:
        raise RuntimeError("FLASK_SECRET_KEY environment variable must be set in production.")
    _secret = secrets.token_hex(32)
    logger.warning("FLASK_SECRET_KEY not set — using temporary random key for debug/testing.")
app.secret_key = _secret

# Validate mailer configuration at startup in production
mailer.verify_mail_config()

# Auto-initialize database schema on startup
if not _is_testing:
    try:
        db.init_db(app)
    except Exception as _e:
        logger.error("Could not auto-initialize DB on startup: %s", _e, exc_info=True)

# Reverse proxy handling
trusted_proxies = int(os.environ.get('TRUSTED_PROXY_COUNT', 1))
if trusted_proxies > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxies, x_proto=trusted_proxies, x_host=trusted_proxies)

# Harden session cookies and enforce request limits
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=64 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)
if os.environ.get('WEBSITE_HOSTNAME'):
    app.config['SESSION_COOKIE_SECURE'] = True

app.teardown_appcontext(db.close_connection)

def get_ip_hash(ip):
    """Derives an isolated key for IP hashing to protect raw secret key."""
    derived_key = hashlib.sha256(app.secret_key.encode('utf-8') + b"|iphash").digest()
    return hmac.new(derived_key, ip.encode('utf-8'), hashlib.sha256).hexdigest()

serializer = URLSafeTimedSerializer(app.secret_key, salt="snip-ad-token")
pending_serializer = URLSafeTimedSerializer(app.secret_key, salt="snip-pending")

def build_short_url(code):
    """Builds the public short URL using BASE_URL if configured, falling back to request.host_url."""
    base = os.environ.get('BASE_URL', '').strip().rstrip('/')
    if base:
        return f"{base}/{code}"
    return request.host_url + code

# Common web crawlers and bot User-Agent fragments to filter click inflation
BOT_UA_PATTERNS = re.compile(
    r'(bot|crawl|spider|slurp|facebookexternalhit|whatsapp|telegrambot|twitterbot|pinterest|discordbot|curl|wget|python-requests|headless)',
    re.IGNORECASE
)

# Periodic maintenance counter
_request_counter = 0
_req_counter_lock = threading.Lock()

@app.before_request
def periodic_maintenance():
    global _request_counter
    with _req_counter_lock:
        _request_counter += 1
        run_cleanup = (_request_counter % 50 == 0)
    if run_cleanup:
        try:
            conn = db.get_db()
            db.cleanup_stale_records(conn)
        except Exception as e:
            logger.warning("Periodic records cleanup encountered error: %s", e)



# ── Security & Context Hooks ─────────────────────────────────

@app.before_request
def setup_request_security():
    """Generates a per-request cryptographically secure nonce for CSP."""
    g.csp_nonce = secrets.token_urlsafe(16)

def generate_csrf_token():
    """Generates or retrieves the active session CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

@app.context_processor
def inject_template_globals():
    return dict(
        csrf_token=generate_csrf_token,
        csp_nonce=getattr(g, 'csp_nonce', '')
    )

@app.before_request
def csrf_protect():
    """Validates CSRF tokens for all state-changing HTTP methods."""
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        # Allow requests explicitly authenticated with an API key
        if request.headers.get('X-API-Key') or request.path.startswith('/api/'):
            return None

        submitted_token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token')
        session_token = session.get('csrf_token')

        if not session_token or not submitted_token or not hmac.compare_digest(session_token, submitted_token):
            logger.warning("CSRF validation failure on %s from IP %s", request.path, request.remote_addr)
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'CSRF verification failed'}), 403
            return render_template('403.html', reason="CSRF token missing or mismatch."), 403


# ── Security Headers ────────────────────────────────────────

@app.after_request
def add_security_headers(response):
    """Injects modern defense-in-depth HTTP security headers with strict CSP."""
    nonce = getattr(g, 'csp_nonce', '')
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https: blob:; "
        "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if os.environ.get('WEBSITE_HOSTNAME') or request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Apply Cache-Control: no-store to every response with a logged-in session
    # and to /dashboard*, /account*, /register*, /forgot-password, /reset-password, /login.
    is_logged_in = 'user_id' in session
    p = request.path
    sensitive_prefixes = ('/dashboard', '/account', '/register', '/forgot-password', '/reset-password', '/login')
    is_sensitive_path = any(p.startswith(prefix) for prefix in sensitive_prefixes)
    if is_logged_in or is_sensitive_path:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'

    return response


# ── JSON Helper ─────────────────────────────────────────────

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


# ── Decorators ──────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access that page.', 'error')
            return redirect(url_for('login'))

        conn = db.get_db()
        user = conn.execute('SELECT id, session_version, email_verified_at FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or user['session_version'] != session.get('session_version'):
            session.clear()
            flash('Your session has expired or was revoked. Please log in again.', 'error')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function


DUMMY_PW_HASH = generate_password_hash("snip-timing-defense-dummy-hash")

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key missing'}), 401

        ip = request.remote_addr or 'unknown'
        conn = db.get_db()
        user = core.get_user_by_api_key(conn, api_key)
        if not user:
            if core.is_rate_limited(f"api_fail:{ip}", max_requests=10, window_seconds=60):
                return jsonify({'error': 'Too many failed API key attempts. Try again later.'}), 429
            return jsonify({'error': 'Invalid API key'}), 401

        if os.environ.get('REQUIRE_VERIFIED_EMAIL_FOR_API') == '1':
            if not user['email_verified_at']:
                return jsonify({'error': 'Email verification required to access API.'}), 403

        g.api_user = user
        return f(*args, **kwargs)
    return decorated_function


# ── Error Handlers ──────────────────────────────────────────

def _wants_json():
    return request.path.startswith('/api/') or request.is_json or 'application/json' in request.headers.get('Accept', '')

@app.errorhandler(400)
def bad_request(e):
    if _wants_json():
        return jsonify({'error': 'Bad Request'}), 400
    return render_template('403.html', reason="Invalid request data."), 400

@app.errorhandler(403)
def forbidden(e):
    if _wants_json():
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('403.html', reason="Access forbidden."), 403

@app.errorhandler(404)
def page_not_found(e):
    if _wants_json():
        return jsonify({'error': 'Resource not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(405)
def method_not_allowed(e):
    if _wants_json():
        return jsonify({'error': 'Method Not Allowed'}), 405
    return render_template('403.html', reason="Method not allowed."), 405

@app.errorhandler(410)
def resource_gone(e):
    if _wants_json():
        return jsonify({'error': 'Resource Gone / Expired'}), 410
    return render_template('expired.html'), 410

@app.errorhandler(413)
def request_entity_too_large(e):
    if _wants_json():
        return jsonify({'error': 'Payload Too Large'}), 413
    return render_template('403.html', reason="Payload exceeds maximum allowed size."), 413

@app.errorhandler(429)
def too_many_requests(e):
    if _wants_json():
        return jsonify({'error': 'Too Many Requests'}), 429
    return render_template('429.html'), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error("Unhandled internal server error: %s", e)
    if _wants_json():
        return jsonify({'error': 'Internal Server Error'}), 500
    return render_template('500.html'), 500


# ── System & Utility Routes ─────────────────────────────────

@app.route('/health')
def health():
    """Health check endpoint for Azure App Service & monitoring probes."""
    try:
        conn = db.get_db()
        conn.execute('SELECT 1').fetchone()
        return jsonify({
            'status': 'healthy',
            'database': 'ok',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as e:
        logger.error("Health check database probe failed: %s", e)
        return jsonify({
            'status': 'unhealthy',
            'database': 'error',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 503

@app.route('/robots.txt')
def robots():
    """Prevents search crawlers from traversing short codes and wasting bandwidth."""
    content = (
        "User-agent: *\n"
        "Disallow: /*/\n"
        "Disallow: /continue/\n"
        "Disallow: /dashboard/\n"
        "Disallow: /api/\n"
        "Allow: /\n"
    )
    return app.response_class(content, mimetype='text/plain')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )


# ── Auth & Static Routes ────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if core.is_rate_limited(f"reg_ip:{ip}", max_requests=5, window_seconds=3600):
            return render_template('429.html'), 429

        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # Input validation
        is_user_valid, user_err = core.validate_username(username)
        if not is_user_valid:
            flash(user_err, 'error')
            return redirect(url_for('register'))

        is_pw_valid, pw_err = core.validate_password(password)
        if not is_pw_valid:
            flash(pw_err, 'error')
            return redirect(url_for('register'))

        is_email_valid, email_res = core.validate_email(email)
        if not is_email_valid:
            flash(email_res, 'error')
            return redirect(url_for('register'))
        email_normalized = email_res

        conn = db.get_db()

        # Explicit username taken error
        if conn.execute('SELECT id FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone():
            flash('Username already taken.', 'error')
            return redirect(url_for('register'))

        # Generic response for existing verified email (anti-enumeration)
        existing_email = conn.execute(
            'SELECT id FROM users WHERE email_normalized = ? AND email_verified_at IS NOT NULL',
            (email_normalized,)
        ).fetchone()

        if existing_email:
            session['pending_register'] = pending_serializer.dumps({
                'email': email,
                'email_normalized': email_normalized,
                'username': username
            })
            flash('If this address can be used to register, a verification code has been sent.', 'info')
            return redirect(url_for('register_verify'))

        ip_hash = get_ip_hash(ip)
        ok_limits, limit_err, _ = otp.check_otp_rate_limits(conn, email_normalized, 'register', ip_hash)
        if not ok_limits:
            flash(limit_err, 'error')
            return redirect(url_for('register'))

        pwhash = generate_password_hash(password)
        pending_payload = json.dumps({'username': username, 'password_hash': pwhash})

        code, _ = otp.create_otp(
            conn, app.secret_key, email_normalized, email, 'register',
            pending_payload=pending_payload, ip_hash=ip_hash
        )

        mail_status = mailer.send_registration_otp(email, code)
        if mail_status == MailStatus.CAP_REACHED:
            flash('Verification emails are temporarily unavailable, please try again shortly.', 'error')
            return redirect(url_for('register'))
        elif not mail_status:
            flash('Failed to send verification email. Please try again shortly.', 'error')
            return redirect(url_for('register'))

        session['pending_register'] = pending_serializer.dumps({
            'email': email,
            'email_normalized': email_normalized,
            'username': username
        })
        flash('A 6-digit verification code has been sent to your email.', 'info')
        return redirect(url_for('register_verify'))

    return render_template('register.html')


@app.route('/register/verify', methods=['GET', 'POST'])
def register_verify():
    pending_raw = session.get('pending_register')
    if not pending_raw:
        flash('No registration in progress. Please register first.', 'error')
        return redirect(url_for('register'))

    try:
        data = pending_serializer.loads(pending_raw, max_age=900)
    except (SignatureExpired, BadSignature):
        session.pop('pending_register', None)
        flash('Verification session expired. Please register again.', 'error')
        return redirect(url_for('register'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if core.is_rate_limited(f"verify_ip:{ip}", max_requests=20, window_seconds=900):
            return render_template('429.html'), 429

        code = request.form.get('code', '').strip()
        conn = db.get_db()

        ok, res = otp.verify_otp(conn, app.secret_key, data['email_normalized'], 'register', code)
        if not ok:
            flash(res, 'error')
            return render_template('verify_email.html', email=data['email'], resend_url='/register/resend', cancel_url='/register')

        payload_raw = res.get('pending_payload')
        if not payload_raw:
            flash('Registration session expired or payload unavailable. Please register again.', 'error')
            return redirect(url_for('register'))

        payload = json.loads(payload_raw)
        username = payload['username']
        pwhash = payload['password_hash']

        if conn.execute('SELECT id FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone():
            flash('Username was claimed by another user. Please choose a different username.', 'error')
            return redirect(url_for('register'))

        plaintext_key, hashed_key = core.generate_api_key()

        conn.execute('''
            INSERT INTO users (username, password_hash, api_key_hash, email, email_normalized, email_verified_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (username, pwhash, hashed_key, res['email_display'], data['email_normalized']))
        conn.commit()

        user = conn.execute('SELECT id, username, session_version FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['session_version'] = user['session_version']
        session['csrf_token'] = secrets.token_hex(32)

        return render_template('register_success.html', api_key=plaintext_key, username=user['username'])

    return render_template('verify_email.html', email=data['email'], resend_url='/register/resend', cancel_url='/register')


@app.route('/register/resend', methods=['POST'])
def register_resend():
    pending_raw = session.get('pending_register')
    if not pending_raw:
        flash('No registration in progress. Please register first.', 'error')
        return redirect(url_for('register'))

    try:
        data = pending_serializer.loads(pending_raw, max_age=900)
    except (SignatureExpired, BadSignature):
        session.pop('pending_register', None)
        flash('Verification session expired. Please register again.', 'error')
        return redirect(url_for('register'))

    ip = request.remote_addr or 'unknown'
    ip_hash = get_ip_hash(ip)
    conn = db.get_db()

    ok_limits, limit_err, _ = otp.check_otp_rate_limits(conn, data['email_normalized'], 'register', ip_hash)
    if not ok_limits:
        flash(limit_err, 'error')
        return redirect(url_for('register_verify'))

    recent_otp = conn.execute('''
        SELECT pending_payload FROM email_otps 
        WHERE email_normalized = ? AND purpose = 'register' AND consumed_at IS NULL
        ORDER BY id DESC LIMIT 1
    ''', (data['email_normalized'],)).fetchone()

    if not recent_otp or not recent_otp['pending_payload']:
        flash('Registration session expired. Please register again.', 'error')
        return redirect(url_for('register'))

    code, _ = otp.create_otp(
        conn, app.secret_key, data['email_normalized'], data['email'], 'register',
        pending_payload=recent_otp['pending_payload'], ip_hash=ip_hash
    )

    mail_status = mailer.send_registration_otp(data['email'], code)
    if mail_status == MailStatus.CAP_REACHED:
        flash('Verification emails are temporarily unavailable, please try again shortly.', 'error')
    elif not mail_status:
        flash('Failed to send verification email. Please try again shortly.', 'error')
    else:
        flash('A new 6-digit verification code has been sent.', 'success')

    return redirect(url_for('register_verify'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if core.is_rate_limited(f"login_ip:{ip}", max_requests=10, window_seconds=300):
            return render_template('429.html'), 429

        identifier = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if core.is_rate_limited(f"login_fail_user:{ip}:{identifier.lower()}", max_requests=5, window_seconds=900):
            flash('Too many failed login attempts for this account. Please wait 15 minutes.', 'error')
            return render_template('login.html'), 429

        conn = db.get_db()
        norm_email = core.normalize_email(identifier) if '@' in identifier else None

        # Login by email matches verified emails only
        if norm_email:
            user = conn.execute(
                'SELECT * FROM users WHERE (email_normalized = ? AND email_verified_at IS NOT NULL) OR username = ? COLLATE NOCASE',
                (norm_email, identifier)
            ).fetchone()
        else:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ? COLLATE NOCASE',
                (identifier,)
            ).fetchone()

        pw_hash = user['password_hash'] if user else DUMMY_PW_HASH
        is_valid = check_password_hash(pw_hash, password)

        if user and is_valid:
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['session_version'] = user['session_version']
            session['csrf_token'] = secrets.token_hex(32)

            return redirect(url_for('dashboard'))

        core.is_rate_limited(f"login_fail_user:{ip}:{identifier.lower()}", max_requests=5, window_seconds=900)
        flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if core.is_rate_limited(f"forgot_ip:{ip}", max_requests=10, window_seconds=3600):
            return render_template('429.html'), 429

        email = request.form.get('email', '').strip()
        is_valid, email_res = core.validate_email(email)
        if not is_valid:
            flash(email_res, 'error')
            return redirect(url_for('forgot_password'))
        email_normalized = email_res

        ip_hash = get_ip_hash(ip)
        conn = db.get_db()

        # Apply OTP cooldown/hourly caps identically whether or not account exists
        ok_limits, limit_err, _ = otp.check_otp_rate_limits(conn, email_normalized, 'reset', ip_hash)
        if not ok_limits:
            flash(limit_err, 'error')
            return redirect(url_for('forgot_password'))

        user = conn.execute(
            'SELECT id, email, username FROM users WHERE email_normalized = ? AND email_verified_at IS NOT NULL',
            (email_normalized,)
        ).fetchone()

        if user:
            code, _ = otp.create_otp(
                conn, app.secret_key, email_normalized, email, 'reset',
                user_id=user['id'], ip_hash=ip_hash
            )
            mailer.send_password_reset_otp(email, code)
        else:
            otp.create_otp(conn, app.secret_key, email_normalized, email, 'reset', user_id=None, ip_hash=ip_hash)

        session['pending_reset'] = pending_serializer.dumps({
            'email': email,
            'email_normalized': email_normalized
        })
        flash('If a verified account exists for this email, a 6-digit recovery code has been sent.', 'info')
        return redirect(url_for('reset_password'))

    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    pending_raw = session.get('pending_reset')
    if not pending_raw:
        flash('No password reset in progress. Please request a code first.', 'error')
        return redirect(url_for('forgot_password'))

    try:
        data = pending_serializer.loads(pending_raw, max_age=900)
    except (SignatureExpired, BadSignature):
        session.pop('pending_reset', None)
        flash('Password reset session expired. Please request a new code.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if core.is_rate_limited(f"reset_verify_ip:{ip}", max_requests=20, window_seconds=900):
            return render_template('429.html'), 429

        code = request.form.get('code', '').strip()
        new_password = request.form.get('password', '')

        is_pw_valid, pw_err = core.validate_password(new_password)
        if not is_pw_valid:
            flash(pw_err, 'error')
            return render_template('reset_password.html', email=data['email'])

        conn = db.get_db()
        ok, res = otp.verify_otp(conn, app.secret_key, data['email_normalized'], 'reset', code)
        if not ok:
            flash(res, 'error')
            return render_template('reset_password.html', email=data['email'])

        user_id = res.get('user_id')
        if not user_id:
            flash('Password reset failed. Please request a new code.', 'error')
            return redirect(url_for('forgot_password'))

        pwhash = generate_password_hash(new_password)
        conn.execute('''
            UPDATE users 
            SET password_hash = ?, session_version = session_version + 1 
            WHERE id = ?
        ''', (pwhash, user_id))
        conn.commit()

        session.pop('pending_reset', None)
        mailer.send_security_alert(
            res['email_display'],
            "Your Snip Password Was Changed",
            "The password for your Snip account was recently updated via email recovery. If you did not authorize this change, please contact support immediately."
        )

        flash('Your password has been reset successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=data['email'])


@app.route('/reset-password/resend', methods=['POST'])
def reset_password_resend():
    pending_raw = session.get('pending_reset')
    if not pending_raw:
        flash('No password reset in progress.', 'error')
        return redirect(url_for('forgot_password'))

    try:
        data = pending_serializer.loads(pending_raw, max_age=900)
    except (SignatureExpired, BadSignature):
        session.pop('pending_reset', None)
        flash('Password reset session expired.', 'error')
        return redirect(url_for('forgot_password'))

    ip = request.remote_addr or 'unknown'
    ip_hash = get_ip_hash(ip)
    conn = db.get_db()

    ok_limits, limit_err, _ = otp.check_otp_rate_limits(conn, data['email_normalized'], 'reset', ip_hash)
    if not ok_limits:
        flash(limit_err, 'error')
        return redirect(url_for('reset_password'))

    user = conn.execute(
        'SELECT id, email FROM users WHERE email_normalized = ? AND email_verified_at IS NOT NULL',
        (data['email_normalized'],)
    ).fetchone()

    if user:
        code, _ = otp.create_otp(
            conn, app.secret_key, data['email_normalized'], data['email'], 'reset',
            user_id=user['id'], ip_hash=ip_hash
        )
        mailer.send_password_reset_otp(data['email'], code)
    else:
        otp.create_otp(conn, app.secret_key, data['email_normalized'], data['email'], 'reset', user_id=None, ip_hash=ip_hash)

    flash('If eligible, a new recovery code has been sent.', 'info')
    return redirect(url_for('reset_password'))




@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method != 'POST':
        abort(405)
    session.clear()
    return redirect(url_for('index'))


# ── Dashboard ───────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    conn = db.get_db()
    uid = session['user_id']

    page = request.args.get('page', 1, type=int)
    if page < 1:
        page = 1
    per_page = 50
    offset = (page - 1) * per_page

    total_links_row = conn.execute('SELECT COUNT(*) AS count FROM links WHERE owner_id = ?', (uid,)).fetchone()
    total_links = total_links_row['count'] if total_links_row else 0
    total_pages = max(1, math.ceil(total_links / per_page))

    links = conn.execute('''
        SELECT links.*, COUNT(clicks.id) AS click_count
        FROM links
        LEFT JOIN clicks ON clicks.link_id = links.id
        WHERE links.owner_id = ?
        GROUP BY links.id
        ORDER BY links.created_at DESC
        LIMIT ? OFFSET ?
    ''', (uid, per_page, offset)).fetchall()

    earnings_data = db.get_earnings(conn, uid)
    total_clicks = sum(link['click_count'] for link in links)

    return render_template('dashboard.html',
                           links=links,
                           earnings=earnings_data['earnings'],
                           network_earnings=earnings_data['network_earnings'],
                           custom_spend=earnings_data['custom_spend'],
                           total_clicks=total_clicks,
                           page=page,
                           total_pages=total_pages,
                           total_links=total_links)


@app.route('/dashboard/live-stats')
@login_required
def dashboard_live_stats():
    conn = db.get_db()
    uid = session['user_id']

    links = conn.execute('''
        SELECT links.id, links.code, COUNT(clicks.id) AS click_count
        FROM links
        LEFT JOIN clicks ON clicks.link_id = links.id
        WHERE links.owner_id = ?
        GROUP BY links.id
    ''', (uid,)).fetchall()

    earnings_data = db.get_earnings(conn, uid)
    total_clicks = sum(row['click_count'] for row in links)

    return jsonify({
        'earnings': earnings_data['earnings'],
        'earnings_formatted': earnings_data['earnings_formatted'],
        'network_earnings': earnings_data['network_earnings'],
        'custom_spend': earnings_data['custom_spend'],
        'total_clicks': total_clicks,
        'links': [{'code': row['code'], 'clicks': row['click_count']} for row in links]
    })




# ── Account Settings ─────────────────────────────────────────

@app.route('/dashboard/account')
@login_required
def dashboard_account():
    conn = db.get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('account.html', user=user)


@app.route('/dashboard/account/change-password', methods=['POST'])
@login_required
def dashboard_account_change_password():
    uid = session['user_id']
    if core.is_rate_limited(f"account_action:{uid}:change_pw", max_requests=5, window_seconds=3600):
        flash('Too many password change attempts. Please try again in an hour.', 'error')
        return redirect(url_for('dashboard_account'))

    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')

    conn = db.get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], current_password):
        flash('Incorrect current password.', 'error')
        return redirect(url_for('dashboard_account'))

    is_pw_valid, pw_err = core.validate_password(new_password)
    if not is_pw_valid:
        flash(pw_err, 'error')
        return redirect(url_for('dashboard_account'))

    pwhash = generate_password_hash(new_password)
    conn.execute('''
        UPDATE users 
        SET password_hash = ?, session_version = session_version + 1 
        WHERE id = ?
    ''', (pwhash, uid))
    conn.commit()

    updated_user = conn.execute('SELECT session_version FROM users WHERE id = ?', (uid,)).fetchone()
    session['session_version'] = updated_user['session_version']

    if user['email']:
        mailer.send_security_alert(
            user['email'],
            "Your Snip Password Was Changed",
            "The password for your Snip account was recently updated. If you did not make this change, please contact support immediately."
        )

    flash('Password updated successfully. Other active sessions have been revoked.', 'success')
    return redirect(url_for('dashboard_account'))


@app.route('/dashboard/account/regenerate-api-key', methods=['POST'])
@login_required
def dashboard_account_regenerate_api_key():
    uid = session['user_id']
    if core.is_rate_limited(f"account_action:{uid}:regen_key", max_requests=5, window_seconds=3600):
        return jsonify({'error': 'Rate limit exceeded. Maximum 5 key regenerations per hour.'}), 429

    current_password = request.form.get('current_password') or (request.json.get('current_password') if request.is_json else None)
    if not current_password:
        return jsonify({'error': 'Current password is required to regenerate API key.'}), 400

    conn = db.get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], current_password):
        return jsonify({'error': 'Incorrect current password.'}), 400

    plaintext_key, hashed_key = core.generate_api_key()
    conn.execute('UPDATE users SET api_key_hash = ? WHERE id = ?', (hashed_key, uid))
    conn.commit()

    if user['email']:
        mailer.send_security_alert(
            user['email'],
            "Your Snip API Key Was Regenerated",
            "Your personal API key was regenerated. Any external applications or CLI integrations using the old key will stop working."
        )

    return jsonify({'api_key': plaintext_key}), 200


@app.route('/dashboard/account/change-email', methods=['POST'])
@login_required
def dashboard_account_change_email():
    uid = session['user_id']
    if core.is_rate_limited(f"account_action:{uid}:change_email", max_requests=5, window_seconds=3600):
        flash('Too many email change requests. Maximum 5 per hour.', 'error')
        return redirect(url_for('dashboard_account'))

    current_password = request.form.get('current_password', '')
    new_email = request.form.get('new_email', '').strip()

    conn = db.get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], current_password):
        flash('Incorrect current password.', 'error')
        return redirect(url_for('dashboard_account'))

    is_valid, email_res = core.validate_email(new_email)
    if not is_valid:
        flash(email_res, 'error')
        return redirect(url_for('dashboard_account'))
    email_normalized = email_res

    existing = conn.execute(
        'SELECT id FROM users WHERE email_normalized = ? AND email_verified_at IS NOT NULL AND id != ?',
        (email_normalized, uid)
    ).fetchone()

    if existing:
        session['pending_email_change'] = pending_serializer.dumps({
            'new_email': new_email,
            'email_normalized': email_normalized
        })
        flash('If this address can be used, a verification code has been sent.', 'info')
        return redirect(url_for('dashboard_verify_email_change'))

    ip = request.remote_addr or 'unknown'
    ip_hash = get_ip_hash(ip)
    ok_limits, limit_err, _ = otp.check_otp_rate_limits(conn, email_normalized, 'change_email', ip_hash)
    if not ok_limits:
        flash(limit_err, 'error')
        return redirect(url_for('dashboard_account'))

    code, _ = otp.create_otp(
        conn, app.secret_key, email_normalized, new_email, 'change_email',
        user_id=uid, ip_hash=ip_hash
    )

    mail_status = mailer.send_change_email_otp(new_email, code)
    if mail_status == MailStatus.CAP_REACHED:
        flash('Verification emails are temporarily unavailable, please try again shortly.', 'error')
        return redirect(url_for('dashboard_account'))
    elif not mail_status:
        flash('Failed to send verification email. Please try again shortly.', 'error')
        return redirect(url_for('dashboard_account'))

    session['pending_email_change'] = pending_serializer.dumps({
        'new_email': new_email,
        'email_normalized': email_normalized
    })
    flash('Verification code sent to your new email address.', 'info')
    return redirect(url_for('dashboard_verify_email_change'))


@app.route('/dashboard/account/verify-email-change', methods=['GET', 'POST'])
@login_required
def dashboard_verify_email_change():
    pending_raw = session.get('pending_email_change')
    if not pending_raw:
        flash('No email change in progress.', 'error')
        return redirect(url_for('dashboard_account'))

    try:
        data = pending_serializer.loads(pending_raw, max_age=900)
    except (SignatureExpired, BadSignature):
        session.pop('pending_email_change', None)
        flash('Email change session expired. Please submit the form again.', 'error')
        return redirect(url_for('dashboard_account'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if core.is_rate_limited(f"verify_ip:{ip}", max_requests=20, window_seconds=900):
            return render_template('429.html'), 429

        code = request.form.get('code', '').strip()
        conn = db.get_db()

        ok, res = otp.verify_otp(conn, app.secret_key, data['email_normalized'], 'change_email', code)
        if not ok:
            flash(res, 'error')
            return render_template('verify_email.html', email=data['new_email'], resend_url='/dashboard/account/resend-email-change', cancel_url='/dashboard/account')

        uid = session['user_id']
        current_user = conn.execute('SELECT email FROM users WHERE id = ?', (uid,)).fetchone()
        old_email = current_user['email'] if current_user else None

        conn.execute('''
            UPDATE users 
            SET email = ?, email_normalized = ?, email_verified_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (res['email_display'], data['email_normalized'], uid))
        conn.commit()

        session.pop('pending_email_change', None)

        if old_email:
            mailer.send_security_alert(
                old_email,
                "Your Snip Email Address Was Changed",
                f"The email address for your Snip account was updated to {res['email_display']}. If you did not make this change, please contact support immediately."
            )

        flash('Email address updated successfully!', 'success')
        return redirect(url_for('dashboard_account'))

    return render_template('verify_email.html', email=data['new_email'], resend_url='/dashboard/account/resend-email-change', cancel_url='/dashboard/account')


@app.route('/dashboard/account/resend-email-change', methods=['POST'])
@login_required
def dashboard_account_resend_email_change():
    pending_raw = session.get('pending_email_change')
    if not pending_raw:
        flash('No email change in progress.', 'error')
        return redirect(url_for('dashboard_account'))

    try:
        data = pending_serializer.loads(pending_raw, max_age=900)
    except (SignatureExpired, BadSignature):
        session.pop('pending_email_change', None)
        flash('Email change session expired.', 'error')
        return redirect(url_for('dashboard_account'))

    ip = request.remote_addr or 'unknown'
    ip_hash = get_ip_hash(ip)
    conn = db.get_db()

    ok_limits, limit_err, _ = otp.check_otp_rate_limits(conn, data['email_normalized'], 'change_email', ip_hash)
    if not ok_limits:
        flash(limit_err, 'error')
        return redirect(url_for('dashboard_verify_email_change'))

    code, _ = otp.create_otp(
        conn, app.secret_key, data['email_normalized'], data['new_email'], 'change_email',
        user_id=session['user_id'], ip_hash=ip_hash
    )

    mail_status = mailer.send_change_email_otp(data['new_email'], code)
    if mail_status == MailStatus.CAP_REACHED:
        flash('Verification emails are temporarily unavailable, please try again shortly.', 'error')
    elif not mail_status:
        flash('Failed to send verification email. Please try again shortly.', 'error')
    else:
        flash('A new verification code has been sent.', 'success')

    return redirect(url_for('dashboard_verify_email_change'))


@app.route('/dashboard/account/logout-all', methods=['POST'])
@login_required
def dashboard_account_logout_all():
    conn = db.get_db()
    conn.execute('UPDATE users SET session_version = session_version + 1 WHERE id = ?', (session['user_id'],))
    conn.commit()
    session.clear()
    flash('You have been logged out of all active sessions.', 'info')
    return redirect(url_for('login'))


def _delete_screenshot_file(code):
    """Safely cleans up any stored screenshot for a deleted link code."""
    screenshots_dir = os.path.join(db.DATA_DIR, 'screenshots')
    filepath = os.path.join(screenshots_dir, f"{code}.jpg")
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
        except OSError:
            pass


@app.route('/dashboard/delete/<code>', methods=['POST'])
@login_required
def dashboard_delete(code):
    """Session-authenticated delete for the web UI."""
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != session['user_id']:
        return jsonify({'error': 'Forbidden'}), 403

    conn.execute('DELETE FROM links WHERE code = ?', (code,))
    conn.commit()
    _delete_screenshot_file(code)
    return jsonify({'message': 'Deleted'}), 200


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
    custom_ad_title = (data.get('custom_ad_title') or '').strip()[:100]
    custom_ad_desc = (data.get('custom_ad_desc') or '').strip()[:300]
    custom_ad_media_type = (data.get('custom_ad_media_type') or 'link').strip()
    if custom_ad_media_type not in ('link', 'video', 'webpage'):
        custom_ad_media_type = 'link'

    if custom_ad_url:
        if not core.is_safe_url(custom_ad_url):
            return False, 'Custom ad URL is invalid or points to an unsafe/private destination.'

    if ad_type == 'custom' and not custom_ad_url:
        return False, 'Destination URL is required for custom ads.'

    return True, {
        'ad_type': ad_type,
        'custom_ad_url': custom_ad_url,
        'custom_ad_title': custom_ad_title,
        'custom_ad_desc': custom_ad_desc,
        'custom_ad_media_type': custom_ad_media_type
    }


@app.route('/dashboard/toggle-ads/<code>', methods=['POST'])
@login_required
def dashboard_toggle_ads(code):
    """Toggle ads monetization on/off for a link."""
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != session['user_id']:
        return jsonify({'error': 'Forbidden'}), 403

    if not link['owner_id']:
        return jsonify({'error': 'Anonymous links cannot enable ads'}), 400

    owner = conn.execute('SELECT email_verified_at FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not owner or not owner['email_verified_at']:
        return jsonify({'error': 'Email verification required to enable monetization.'}), 403

    new_val = 0 if link['ads_enabled'] else 1
    if new_val == 1 and link['ad_type'] == 'custom' and link['custom_ad_url']:
        if not core.is_safe_url(link['custom_ad_url']):
            return jsonify({'error': 'Cannot enable ads: custom ad URL is invalid or unsafe.'}), 400

    conn.execute('UPDATE links SET ads_enabled = ? WHERE code = ?', (new_val, code))
    conn.commit()
    return jsonify({'message': 'Updated', 'ads_enabled': bool(new_val)}), 200


@app.route('/dashboard/configure-ad/<code>', methods=['POST'])
@login_required
def dashboard_configure_ad(code):
    """Configure ad mode (network vs custom) and ad creative details for a link."""
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != session['user_id']:
        return jsonify({'error': 'Forbidden'}), 403

    if not link['owner_id']:
        return jsonify({'error': 'Anonymous links cannot configure ads.'}), 400

    owner = conn.execute('SELECT email_verified_at FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not owner or not owner['email_verified_at']:
        return jsonify({'error': 'Email verification required to configure ads.'}), 403

    data = request.get_json() if request.is_json else request.form
    ok, cleaned = _clean_ad_config(data)
    if not ok:
        return jsonify({'error': cleaned}), 400

    conn.execute('''
        UPDATE links SET
            ad_type = ?,
            custom_ad_url = ?,
            custom_ad_title = ?,
            custom_ad_desc = ?,
            custom_ad_media_type = ?,
            ads_enabled = 1
        WHERE code = ?
    ''', (cleaned['ad_type'], cleaned['custom_ad_url'], cleaned['custom_ad_title'],
          cleaned['custom_ad_desc'], cleaned['custom_ad_media_type'], code))
    conn.commit()

    return jsonify({
        'message': 'Ad configured successfully',
        'ad_type': cleaned['ad_type'],
        'custom_ad_url': cleaned['custom_ad_url'],
        'custom_ad_title': cleaned['custom_ad_title'],
        'custom_ad_desc': cleaned['custom_ad_desc'],
        'custom_ad_media_type': cleaned['custom_ad_media_type'],
        'ads_enabled': True
    }), 200


# ── Shorten Routes ──────────────────────────────────────────

@app.route('/api/shorten', methods=['POST'])
def shorten_api():
    api_key = request.headers.get('X-API-Key')
    if api_key:
        conn = db.get_db()
        user = core.get_user_by_api_key(conn, api_key)
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        return _shorten_logic(user['id'])
    return _shorten_logic(None)


@app.route('/shorten', methods=['POST'])
def shorten_web():
    owner_id = session.get('user_id')
    if owner_id is not None:
        conn = db.get_db()
        if not conn.execute('SELECT id FROM users WHERE id = ?', (owner_id,)).fetchone():
            session.clear()
            owner_id = None
    return _shorten_logic(owner_id)


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
    core.queue_external_check(app, link_id, url)
    core.capture_screenshot(code, url, db.DATA_DIR)

    short_url = build_short_url(code)
    return jsonify({
        'code': code,
        'short_url': short_url,
        'original_url': url,
        'expires_at': expires_at,
        'heuristic_flags': heuristic_flags
    })


# ── Redirect Flow ───────────────────────────────────────────

@app.route('/<code>')
def redirect_link(code):
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        # Fallback to case-insensitive lookup for user aliases
        link = conn.execute('SELECT * FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()

    if not link:
        abort(404)

    # Expiry validation
    if link['expires_at']:
        try:
            expiry = _parse_link_expiry(link['expires_at'])
            if expiry and datetime.now(timezone.utc) >= expiry:
                return render_template('expired.html', reason="This link has expired."), 410
        except (ValueError, TypeError):
            pass

    # Open redirect re-validation: guarantee destination is still safe
    target_url = link['original_url']
    if not core.validate_url_at_redirect(target_url):
        logger.warning("Blocked redirect to invalid/unsafe URL for code %s: %s", code, target_url)
        abort(403)

    # Bot / crawler filtering for clicks and analytics
    user_agent = request.headers.get('User-Agent', '')
    is_crawler = bool(BOT_UA_PATTERNS.search(user_agent))
    ip = request.remote_addr or 'unknown'

    if not is_crawler:
        ip_hash = get_ip_hash(ip)
        # Check for rapid click spam from same IP on same link within 30 seconds
        recent = conn.execute('''
            SELECT id FROM clicks 
            WHERE link_id = ? AND ip_hash = ? AND timestamp >= datetime('now', '-30 seconds')
        ''', (link['id'], ip_hash)).fetchone()

        if not recent:
            referrer = (request.referrer or '')[:512] if request.referrer else None
            conn.execute(
                'INSERT INTO clicks (link_id, ip_hash, referrer) VALUES (?, ?, ?)',
                (link['id'], ip_hash, referrer)
            )
            conn.commit()

    # Flow 1 — Malicious warning
    if link['safety_status'] == 'malicious' and request.args.get('confirm') != '1':
        return render_template('warning.html', code=code)

    # Flow 2 — Ad interstitial
    # Only show ads if ads are enabled and visitor is not a bot/crawler
    if link['ads_enabled'] and not is_crawler:
        # Rate limit ad nonce issuance per IP and per link (max 5 per 60s)
        ad_rate_key = f"ad:{ip}:{link['id']}"
        if core.is_rate_limited(ad_rate_key, max_requests=5, window_seconds=60):
            # Velocity exceeded: skip interstitial and redirect directly without crediting
            return redirect(target_url)

        # Re-validate custom ad URL at render time
        effective_ad_type = link['ad_type']
        effective_custom_url = link['custom_ad_url']
        if effective_ad_type == 'custom':
            if not effective_custom_url or not core.is_safe_url(effective_custom_url):
                # Unsafe custom ad: gracefully fall back to network ad slot
                effective_ad_type = 'network'
                effective_custom_url = ''

        # Prepare YouTube embed URL cleanly if applicable
        safe_embed = None
        if link['custom_ad_media_type'] == 'video' and effective_custom_url:
            safe_embed = core.extract_youtube_embed(effective_custom_url)

        nonce = secrets.token_urlsafe(16)
        conn.execute('INSERT INTO ad_nonces (nonce, link_id) VALUES (?, ?)', (nonce, link['id']))
        conn.commit()

        # Token payload with issue timestamp and client binding
        iat = int(time.time())
        client_binding = hashlib.sha256(f"{ip}|{user_agent}".encode('utf-8')).hexdigest()[:16]
        token = serializer.dumps({
            'link_id': link['id'],
            'nonce': nonce,
            'iat': iat,
            'client_binding': client_binding
        })
        return render_template(
            'ad_interstitial.html',
            token=token,
            link=link,
            safe_embed=safe_embed,
            effective_ad_type=effective_ad_type,
            effective_custom_url=effective_custom_url
        )

    # Flow 3 — Direct redirect
    return redirect(target_url)


@app.route('/continue/<token>')
def continue_ad(token):
    try:
        data = serializer.loads(token, max_age=120)
    except SignatureExpired:
        return render_template('expired.html', reason="Ad transit countdown expired. Please refresh the short link."), 400
    except BadSignature:
        abort(404)

    # Enforce minimum elapsed time (AD_MIN_SECONDS, default 10s minus 1s grace for clock skew)
    iat = data.get('iat', 0)
    ad_min_sec = float(os.environ.get('AD_MIN_SECONDS', 10))
    elapsed = time.time() - iat
    if elapsed < (ad_min_sec - 1.0):
        return render_template('expired.html', reason="Ad transit countdown was not completed."), 400

    # Verify client binding
    client_ip = request.remote_addr or 'unknown'
    client_ua = request.headers.get('User-Agent', '')
    curr_binding = hashlib.sha256(f"{client_ip}|{client_ua}".encode('utf-8')).hexdigest()[:16]
    if not hmac.compare_digest(data.get('client_binding', ''), curr_binding):
        return render_template('403.html', reason="Security token validation failure: bound to another client."), 403

    nonce = data.get('nonce')
    link_id = data.get('link_id')

    conn = db.get_db()

    # Execute consumption and validation in a single atomic transaction
    cur = conn.execute(
        'UPDATE ad_nonces SET consumed_at = CURRENT_TIMESTAMP '
        'WHERE nonce = ? AND consumed_at IS NULL', (nonce,)
    )
    if cur.rowcount == 0:
        conn.rollback()
        return render_template('expired.html', reason="Ad transit token has already been consumed."), 400

    link = conn.execute('SELECT * FROM links WHERE id = ?', (link_id,)).fetchone()
    if not link:
        conn.rollback()
        abort(404)

    # Re-check expiry
    if link['expires_at']:
        try:
            expiry = _parse_link_expiry(link['expires_at'])
            if expiry and datetime.now(timezone.utc) >= expiry:
                conn.rollback()
                return render_template('expired.html', reason="Link has expired."), 410
        except (ValueError, TypeError):
            pass

    # Re-check safety status
    if link['safety_status'] == 'malicious':
        conn.rollback()
        return render_template('warning.html', code=link['code'])

    # Re-check destination URL safety
    target_url = link['original_url']
    if not core.validate_url_at_redirect(target_url):
        conn.rollback()
        abort(403)

    # Record monetization economics if eligible:
    # Must have an authenticated owner with verified email, not be a crawler, and rate-limited to once per 30s per (link_id, ip_hash)
    if link['owner_id'] and not BOT_UA_PATTERNS.search(client_ua):
        owner = conn.execute('SELECT email_verified_at FROM users WHERE id = ?', (link['owner_id'],)).fetchone()
        if owner and owner['email_verified_at']:
            ip_hash = get_ip_hash(client_ip)
            recent = conn.execute('''
                SELECT id FROM ad_ledger
                WHERE link_id = ? AND ip_hash = ? AND timestamp >= datetime('now', '-30 seconds')
            ''', (link['id'], ip_hash)).fetchone()

            if not recent:
                amount_micros = -10_000 if link['ad_type'] == 'custom' else 20_000
                conn.execute(
                    'INSERT INTO ad_ledger (link_id, owner_id, link_code, amount_micros, ip_hash) VALUES (?, ?, ?, ?, ?)',
                    (link['id'], link['owner_id'], link['code'], amount_micros, ip_hash)
                )

    conn.commit()
    return redirect(target_url)


# ── API Endpoints ───────────────────────────────────────────

@app.route('/api/stats/<code>', methods=['GET'])
@require_api_key
def api_stats(code):
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != g.api_user['id']:
        return jsonify({'error': 'Forbidden'}), 403

    clicks = conn.execute(
        'SELECT COUNT(*) AS count FROM clicks WHERE link_id = ?',
        (link['id'],)
    ).fetchone()['count']

    return jsonify({
        'code': link['code'],
        'original_url': link['original_url'],
        'created_at': link['created_at'],
        'safety_status': link['safety_status'],
        'clicks': clicks
    })


@app.route('/api/<code>', methods=['DELETE'])
@require_api_key
def api_delete(code):
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != g.api_user['id']:
        return jsonify({'error': 'Forbidden'}), 403

    conn.execute('DELETE FROM links WHERE code = ?', (code,))
    conn.commit()
    _delete_screenshot_file(code)
    return jsonify({'message': 'Deleted successfully'})


@app.route('/api/analytics', methods=['GET'])
@require_api_key
def api_analytics():
    conn = db.get_db()
    limit_str = request.args.get('limit', '5')
    try:
        limit = int(limit_str)
        if limit < 1 or limit > 100:
            return jsonify({'error': 'Limit must be an integer between 1 and 100.'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Limit must be a valid integer.'}), 400

    top_links = conn.execute('''
        SELECT links.code, COUNT(clicks.id) AS click_count
        FROM links
        LEFT JOIN clicks ON links.id = clicks.link_id
        WHERE links.owner_id = ?
        GROUP BY links.id
        ORDER BY click_count DESC
        LIMIT ?
    ''', (g.api_user['id'], limit)).fetchall()

    return jsonify([
        {'code': row['code'], 'clicks': row['click_count']}
        for row in top_links
    ])


# ── QR Code Routes ──────────────────────────────────────────

_qr_cache = {}
_qr_cache_lock = threading.Lock()
_QR_CACHE_MAX = 256

def _generate_qr(data, style='basic'):
    """Generate a QR code image and return it as bytes."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=12,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)

    if style == 'styled':
        img = qr.make_image(
            image_factory=StyledPilImage,
            module_drawer=RoundedModuleDrawer(),
            color_mask=RadialGradiantColorMask(
                back_color=(4, 4, 7),
                center_color=(255, 255, 255),
                edge_color=(59, 130, 246),
            ),
        )
    else:
        img = qr.make_image(fill_color='black', back_color='white')

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf

def _get_cached_qr(data, style='basic'):
    """In-memory bounded LRU cache for generated QR PNG bytes."""
    key = (data, style)
    with _qr_cache_lock:
        if key in _qr_cache:
            val = _qr_cache.pop(key)
            _qr_cache[key] = val
            return val

    val = _generate_qr(data, style).getvalue()
    with _qr_cache_lock:
        if len(_qr_cache) >= _QR_CACHE_MAX:
            _qr_cache.pop(next(iter(_qr_cache)))
        _qr_cache[key] = val
    return val


@app.route('/qr/<code>')
def qr_basic(code):
    """Serve a basic QR code for a short link with caching and rate limiting."""
    if not re.fullmatch(r'^[A-Za-z0-9_-]{1,30}$', code):
        abort(404)

    ip = request.remote_addr or 'unknown'
    if core.is_rate_limited(f"qr:{ip}", max_requests=30, window_seconds=60):
        return render_template('429.html'), 429

    conn = db.get_db()
    link = conn.execute('SELECT code FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)

    short_url = build_short_url(code)
    qr_data = _get_cached_qr(short_url, style='basic')
    return app.response_class(
        qr_data,
        mimetype='image/png',
        headers={
            'Cache-Control': 'public, max-age=3600',
            'X-Content-Type-Options': 'nosniff'
        }
    )


@app.route('/qr/<code>/styled')
def qr_styled(code):
    """Serve a styled QR code with gradient."""
    if not re.fullmatch(r'^[A-Za-z0-9_-]{1,30}$', code):
        abort(404)

    ip = request.remote_addr or 'unknown'
    if core.is_rate_limited(f"qr:{ip}", max_requests=30, window_seconds=60):
        return render_template('429.html'), 429

    conn = db.get_db()
    link = conn.execute('SELECT code FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)

    short_url = build_short_url(code)
    qr_data = _get_cached_qr(short_url, style='styled')
    return app.response_class(
        qr_data,
        mimetype='image/png',
        headers={
            'Cache-Control': 'public, max-age=3600',
            'X-Content-Type-Options': 'nosniff'
        }
    )


@app.route('/qr/<code>/download')
def qr_download(code):
    """Download styled QR code as PNG file."""
    if not re.fullmatch(r'^[A-Za-z0-9_-]{1,30}$', code):
        abort(404)

    ip = request.remote_addr or 'unknown'
    if core.is_rate_limited(f"qr:{ip}", max_requests=30, window_seconds=60):
        return render_template('429.html'), 429

    conn = db.get_db()
    link = conn.execute('SELECT code FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)

    short_url = build_short_url(code)
    qr_data = _get_cached_qr(short_url, style='styled')
    return app.response_class(
        qr_data,
        mimetype='image/png',
        headers={
            'Content-Disposition': f'attachment; filename=snip-qr-{code}.png',
            'Cache-Control': 'public, max-age=3600',
            'X-Content-Type-Options': 'nosniff'
        }
    )


@app.route('/dashboard/qr/<code>')
@login_required
def dashboard_qr(code):
    if not re.fullmatch(r'^[A-Za-z0-9_-]{1,30}$', code):
        abort(404)
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)
    if link['owner_id'] != session['user_id']:
        flash('You can only manage your own links.', 'error')
        return redirect(url_for('dashboard'))
    short_url = build_short_url(code)
    return render_template('qr.html', link=link, short_url=short_url)


# ── Website Previews ────────────────────────────────────────

@app.route('/preview/<code>.jpg')
def preview_image(code):
    """Serves the locally saved website snapshot securely."""
    # Strict regex check prevents directory traversal attacks
    if not re.fullmatch(r'^[A-Za-z0-9_-]{1,30}$', code):
        abort(404)

    conn = db.get_db()
    link = conn.execute('SELECT id FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)

    screenshots_dir = os.path.join(db.DATA_DIR, 'screenshots')
    filename = f"{code}.jpg"
    filepath = os.path.join(screenshots_dir, filename)
    
    if os.path.exists(filepath):
        resp = make_response(send_from_directory(screenshots_dir, filename, mimetype='image/jpeg'))
        resp.headers['Cache-Control'] = 'public, max-age=86400'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['Content-Disposition'] = 'inline'
        return resp
    else:
        svg = (
            '<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">'
            '<rect width="100%" height="100%" fill="#16213e"/>'
            '<text x="50%" y="50%" font-family="sans-serif" font-size="24" fill="#a0a3b8" text-anchor="middle" dominant-baseline="middle">Capturing snapshot...</text>'
            '<text x="50%" y="54%" font-family="sans-serif" font-size="14" fill="#6b7190" text-anchor="middle" dominant-baseline="middle">Try hovering again in a few seconds.</text>'
            '</svg>'
        )
        resp = make_response(svg)
        resp.mimetype = 'image/svg+xml'
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['Content-Disposition'] = 'inline'
        return resp


# ── Entry Point ─────────────────────────────────────────────

if __name__ == '__main__':
    db.init_db(app)
    is_dev = os.environ.get('FLASK_DEBUG') == '1'
    app.run(debug=is_dev)

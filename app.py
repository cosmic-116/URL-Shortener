import os
import re
import time
import secrets
import logging
import threading
import hmac
from datetime import datetime, timezone, timedelta
from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, session, g, abort, send_from_directory)
from werkzeug.middleware.proxy_fix import ProxyFix

import db
import core
import mailer
from blueprints import register_blueprints
from blueprints.helpers import (
    build_short_url, get_ip_hash, get_json_payload, login_required,
    require_api_key, DUMMY_PW_HASH, BOT_UA_PATTERNS, get_ad_serializer,
    get_pending_serializer, _clean_ad_config, _shorten_logic, _delete_screenshot_file
)

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
default_proxies = 1 if os.environ.get('WEBSITE_HOSTNAME') else 0
trusted_proxies = int(os.environ.get('TRUSTED_PROXY_COUNT', default_proxies))
if trusted_proxies > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxies, x_proto=trusted_proxies, x_host=trusted_proxies)

# Harden session cookies and enforce request limits
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=not (_is_debug or _is_testing),
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=64 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

app.teardown_appcontext(db.close_connection)

from itsdangerous import URLSafeTimedSerializer

# Serializer access for backwards compatibility
serializer = URLSafeTimedSerializer(app.secret_key, salt="snip-ad-token")
pending_serializer = URLSafeTimedSerializer(app.secret_key, salt="snip-pending")

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
        # Only exempt programmatic REST API endpoints
        if request.path.startswith('/api/'):
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
        "frame-src 'self' https: data: https://www.youtube.com https://www.youtube-nocookie.com; "
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
    if p.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'

    return response


# ── Error Handlers ──────────────────────────────────────────

def _wants_json():
    return request.path.startswith('/api/') or request.is_json or 'application/json' in request.headers.get('Accept', '')

@app.errorhandler(400)
def bad_request(e):
    if _wants_json():
        return jsonify({'error': 'Bad Request'}), 400
    return render_template('400.html', reason="Invalid request data."), 400

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
    return render_template('405.html', reason="Method not allowed."), 405

@app.errorhandler(410)
def resource_gone(e):
    if _wants_json():
        return jsonify({'error': 'Resource Gone / Expired'}), 410
    return render_template('expired.html'), 410

@app.errorhandler(413)
def request_entity_too_large(e):
    if _wants_json():
        return jsonify({'error': 'Payload Too Large'}), 413
    return render_template('413.html', reason="Payload exceeds maximum allowed size."), 413

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
        "Disallow: /qr/\n"
        "Disallow: /preview/\n"
        "Disallow: /continue/\n"
        "Disallow: /dashboard/\n"
        "Disallow: /api/\n"
        "Disallow: /account\n"
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


# ── Root Landing Page ───────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── Register Blueprints ─────────────────────────────────────

register_blueprints(app)

# Alias blueprint rules so both url_for('login') and url_for('auth.login') work seamlessly
for rule in list(app.url_map.iter_rules()):
    if '.' in rule.endpoint:
        simple_endpoint = rule.endpoint.split('.', 1)[1]
        if simple_endpoint not in app.url_map._rules_by_endpoint:
            app.url_map._rules_by_endpoint[simple_endpoint] = app.url_map._rules_by_endpoint[rule.endpoint]


# ── Entry Point ─────────────────────────────────────────────

if __name__ == '__main__':
    db.init_db(app)
    is_dev = os.environ.get('FLASK_DEBUG') == '1'
    app.run(debug=is_dev)

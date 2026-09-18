import os
import io
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from functools import wraps
import sqlite3

import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers.pil import RoundedModuleDrawer, CircleModuleDrawer
from qrcode.image.styles.colormasks import RadialGradiantColorMask
from PIL import Image

from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, session, g, abort, flash)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

import db
import core

app = Flask(__name__)

# Production: FLASK_SECRET_KEY MUST be set as an env var.
# Dev fallback generates a random key (sessions reset on restart — that's fine locally).
_secret = os.environ.get('FLASK_SECRET_KEY')
if not _secret:
    import warnings
    _secret = secrets.token_hex(32)
    warnings.warn(
        "FLASK_SECRET_KEY not set — using a random key. "
        "Sessions will NOT survive app restarts. "
        "Set it in Azure: az webapp config appsettings set --settings FLASK_SECRET_KEY=<your-64-char-hex>",
        stacklevel=1,
    )
app.secret_key = _secret

# Harden session cookies for production
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
# Set Secure flag only when running behind HTTPS (Azure always does)
if os.environ.get('WEBSITE_HOSTNAME'):  # Azure sets this automatically
    app.config['SESSION_COOKIE_SECURE'] = True

app.teardown_appcontext(db.close_connection)

serializer = URLSafeTimedSerializer(app.secret_key)


# ── Decorators ──────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access that page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key missing'}), 401

        hashed_key = core.hash_api_key(api_key)
        conn = db.get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE api_key_hash = ?', (hashed_key,)
        ).fetchone()

        if not user:
            return jsonify({'error': 'Invalid API key'}), 401

        g.api_user = user
        return f(*args, **kwargs)
    return decorated_function


# ── Error Handlers ──────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# ── Auth Routes ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('register'))

        conn = db.get_db()

        if conn.execute('SELECT id FROM users WHERE username = ?',
                        (username,)).fetchone():
            flash('Username already taken.', 'error')
            return redirect(url_for('register'))

        pwhash = generate_password_hash(password)
        plaintext_key, hashed_key = core.generate_api_key()

        conn.execute(
            'INSERT INTO users (username, password_hash, api_key_hash) VALUES (?, ?, ?)',
            (username, pwhash, hashed_key))
        conn.commit()

        # The plaintext key is shown exactly once — the user must save it now.
        flash(f'Account created! Your API key (save it now — it won\'t be shown again): {plaintext_key}', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = db.get_db()

        user = conn.execute('SELECT * FROM users WHERE username = ?',
                            (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))

        flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ── Dashboard ───────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    conn = db.get_db()
    uid = session['user_id']

    # Fetch links with per-link click count
    links = conn.execute('''
        SELECT links.*, COUNT(clicks.id) AS click_count
        FROM links
        LEFT JOIN clicks ON clicks.link_id = links.id
        WHERE links.owner_id = ?
        GROUP BY links.id
        ORDER BY links.created_at DESC
    ''', (uid,)).fetchall()

    # Aggregate totals
    earnings_row = conn.execute('''
        SELECT COALESCE(SUM(al.amount), 0) AS total
        FROM ad_ledger al
        JOIN links l ON l.id = al.link_id
        WHERE l.owner_id = ?
    ''', (uid,)).fetchone()
    earnings = earnings_row['total']

    total_clicks = sum(link['click_count'] for link in links)

    return render_template('dashboard.html',
                           links=links,
                           earnings=earnings,
                           total_clicks=total_clicks)


@app.route('/dashboard/delete/<code>', methods=['POST'])
@login_required
def dashboard_delete(code):
    """Session-authenticated delete for the web UI."""
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?',
                        (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != session['user_id']:
        return jsonify({'error': 'Forbidden'}), 403

    conn.execute('DELETE FROM links WHERE code = ?', (code,))
    conn.commit()
    return jsonify({'message': 'Deleted'}), 200


# ── Shorten Routes ──────────────────────────────────────────

@app.route('/api/shorten', methods=['POST'])
def shorten_api():
    api_key = request.headers.get('X-API-Key')
    if api_key:
        hashed_key = core.hash_api_key(api_key)
        conn = db.get_db()
        user = conn.execute('SELECT id FROM users WHERE api_key_hash = ?',
                            (hashed_key,)).fetchone()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        return _shorten_logic(user['id'])
    return _shorten_logic(None)


@app.route('/shorten', methods=['POST'])
def shorten_web():
    owner_id = session.get('user_id')
    # Guard against stale sessions (user deleted / DB recreated)
    if owner_id is not None:
        conn = db.get_db()
        if not conn.execute('SELECT id FROM users WHERE id = ?', (owner_id,)).fetchone():
            session.clear()
            owner_id = None
    return _shorten_logic(owner_id)


def _shorten_logic(owner_id):
    ip = request.remote_addr
    if core.is_rate_limited(ip):
        return jsonify({'error': 'Rate limit exceeded. Try again shortly.'}), 429

    data = request.get_json() if request.is_json else request.form
    url = data.get('url')
    alias = data.get('alias')
    ads_enabled = data.get('ads_enabled') in ('true', 'on', '1', True)

    if not isinstance(url, str) or not url.strip():
        return jsonify({'error': 'URL is required.'}), 400

    url = url.strip()

    if not core.is_safe_url(url):
        return jsonify({'error': 'Invalid or unsafe URL. Only http/https with public hosts allowed.'}), 400

    conn = db.get_db()

    # 1. Alias validation
    code = None
    if alias and isinstance(alias, str) and alias.strip():
        is_valid, result = core.validate_alias(alias.strip())
        if not is_valid:
            return jsonify({'error': result}), 400
        code = result
        if not core.is_code_available(conn, code):
            return jsonify({'error': 'Alias already in use. Choose another.'}), 409

    # 2. Heuristic safety check
    heuristic_flags = core.heuristic_check(url)
    initial_safety = 'pending'

    cur = conn.cursor()
    cur.execute('''
        INSERT INTO links (original_url, owner_id, ads_enabled, safety_status)
        VALUES (?, ?, ?, ?)
    ''', (url, owner_id, ads_enabled, initial_safety))
    link_id = cur.lastrowid

    if not code:
        code = core.generate_short_code(conn)

    try:
        cur.execute('UPDATE links SET code = ? WHERE id = ?', (code, link_id))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({'error': 'Code collision. Please try again.'}), 409

    # 3. Fire-and-forget background safety scan
    core.queue_external_check(app, link_id, url)
    
    # 4. Background screenshot snapshot
    core.capture_screenshot(code, url, db.DATA_DIR)

    short_url = request.host_url + code
    return jsonify({
        'code': code,
        'short_url': short_url,
        'original_url': url,
        'heuristic_flags': heuristic_flags
    })


# ── Redirect Flow ───────────────────────────────────────────

@app.route('/<code>')
def redirect_link(code):
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?',
                        (code,)).fetchone()

    if not link:
        abort(404)

    # Expiry
    if link['expires_at']:
        try:
            expiry = datetime.strptime(
                link['expires_at'], '%Y-%m-%d %H:%M:%S'
            ).replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= expiry:
                return render_template('expired.html'), 410
        except ValueError:
            pass  # Malformed date — treat as non-expiring

    # Record click
    ip = request.remote_addr
    ip_hash = hmac.new(
        app.secret_key.encode(), ip.encode(), hashlib.sha256
    ).hexdigest()

    conn.execute(
        'INSERT INTO clicks (link_id, ip_hash, referrer) VALUES (?, ?, ?)',
        (link['id'], ip_hash, request.referrer))
    conn.commit()

    # Flow 1 — Malicious warning
    if link['safety_status'] == 'malicious' and request.args.get('confirm') != '1':
        return render_template('warning.html', code=code)

    # Flow 2 — Ad interstitial
    if link['ads_enabled']:
        nonce = secrets.token_urlsafe(16)
        conn.execute(
            'INSERT INTO ad_nonces (nonce, link_id) VALUES (?, ?)',
            (nonce, link['id']))
        conn.commit()
        token = serializer.dumps({'link_id': link['id'], 'nonce': nonce})
        return render_template('ad_interstitial.html', token=token)

    # Flow 3 — Direct redirect
    return redirect(link['original_url'])


@app.route('/continue/<token>')
def continue_ad(token):
    try:
        data = serializer.loads(token, max_age=30)
    except SignatureExpired:
        return render_template('expired.html'), 400
    except BadSignature:
        abort(404)

    nonce = data.get('nonce')
    link_id = data.get('link_id')

    conn = db.get_db()

    # Atomically consume the nonce — prevents replay
    cur = conn.execute(
        'UPDATE ad_nonces SET consumed_at = CURRENT_TIMESTAMP '
        'WHERE nonce = ? AND consumed_at IS NULL', (nonce,))
    if cur.rowcount == 0:
        return render_template('expired.html'), 400

    conn.execute(
        'INSERT INTO ad_ledger (link_id, amount) VALUES (?, ?)',
        (link_id, 0.05))
    conn.commit()

    link = conn.execute('SELECT original_url FROM links WHERE id = ?',
                        (link_id,)).fetchone()
    if not link:
        abort(404)

    return redirect(link['original_url'])


# ── API Endpoints ───────────────────────────────────────────

@app.route('/api/stats/<code>', methods=['GET'])
@require_api_key
def api_stats(code):
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?',
                        (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != g.api_user['id']:
        return jsonify({'error': 'Forbidden'}), 403

    clicks = conn.execute(
        'SELECT COUNT(*) AS count FROM clicks WHERE link_id = ?',
        (link['id'],)).fetchone()['count']

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
    link = conn.execute('SELECT * FROM links WHERE code = ?',
                        (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != g.api_user['id']:
        return jsonify({'error': 'Forbidden'}), 403

    conn.execute('DELETE FROM links WHERE code = ?', (code,))
    conn.commit()
    return jsonify({'message': 'Deleted successfully'})


@app.route('/api/analytics', methods=['GET'])
@require_api_key
def api_analytics():
    conn = db.get_db()
    limit = request.args.get('limit', 5, type=int)

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

def _generate_qr(data, style='basic'):
    """Generate a QR code image and return it as bytes.
    style: 'basic' = simple dark-on-light
           'styled' = rounded modules with radial gradient (red→blue)
    """
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
                back_color=(15, 15, 26),       # --bg (#0f0f1a)
                center_color=(233, 69, 96),    # --red
                edge_color=(76, 110, 245),     # --blue
            ),
        )
    else:
        img = qr.make_image(fill_color='#e94560', back_color='#0f0f1a')

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf


@app.route('/qr/<code>')
def qr_basic(code):
    """Serve a basic themed QR code for a short link."""
    conn = db.get_db()
    link = conn.execute('SELECT code FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)
    short_url = request.host_url + code
    buf = _generate_qr(short_url, style='basic')
    return app.response_class(buf.getvalue(), mimetype='image/png')


@app.route('/qr/<code>/styled')
def qr_styled(code):
    """Serve a creative styled QR code with rounded modules and gradient."""
    conn = db.get_db()
    link = conn.execute('SELECT code FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)
    short_url = request.host_url + code
    buf = _generate_qr(short_url, style='styled')
    return app.response_class(buf.getvalue(), mimetype='image/png')


@app.route('/qr/<code>/download')
def qr_download(code):
    """Download the styled QR code as a PNG file."""
    conn = db.get_db()
    link = conn.execute('SELECT code FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)
    short_url = request.host_url + code
    buf = _generate_qr(short_url, style='styled')
    return app.response_class(
        buf.getvalue(),
        mimetype='image/png',
        headers={'Content-Disposition': f'attachment; filename=snip-qr-{code}.png'}
    )


@app.route('/dashboard/qr/<code>')
@login_required
def dashboard_qr(code):
    """QR management page — preview both styles & download."""
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ?', (code,)).fetchone()
    if not link:
        abort(404)
    if link['owner_id'] != session['user_id']:
        flash('You can only manage your own links.', 'error')
        return redirect(url_for('dashboard'))
    short_url = request.host_url + code
    return render_template('qr.html', link=link, short_url=short_url)


# ── Website Previews ────────────────────────────────────────

@app.route('/preview/<code>.jpg')
def preview_image(code):
    """Serves the locally saved website snapshot, or a loading placeholder."""
    from flask import send_file, make_response
    screenshots_dir = os.path.join(db.DATA_DIR, 'screenshots')
    filepath = os.path.join(screenshots_dir, f"{code}.jpg")
    
    if os.path.exists(filepath):
        resp = make_response(send_file(filepath, mimetype='image/jpeg'))
        resp.headers['Cache-Control'] = 'public, max-age=86400'
        return resp
    else:
        # Fallback while generating (must NOT be cached by browser!)
        svg = f'''<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
            <rect width="100%" height="100%" fill="#16213e"/>
            <text x="50%" y="50%" font-family="sans-serif" font-size="24" fill="#a0a3b8" text-anchor="middle" dominant-baseline="middle">Capturing snapshot...</text>
            <text x="50%" y="54%" font-family="sans-serif" font-size="14" fill="#6b7190" text-anchor="middle" dominant-baseline="middle">Try hovering again in a few seconds.</text>
        </svg>'''
        resp = make_response(svg)
        resp.mimetype = 'image/svg+xml'
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return resp


# ── Entry Point ─────────────────────────────────────────────

if __name__ == '__main__':
    db.init_db(app)
    is_dev = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=is_dev)

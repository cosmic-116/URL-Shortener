import os
import re
import time
import secrets
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from flask import (Blueprint, request, render_template, redirect,
                   url_for, abort, make_response, send_from_directory)
from itsdangerous import SignatureExpired, BadSignature

import db
import core
from blueprints.helpers import (get_ip_hash, get_ad_serializer, _parse_link_expiry,
                                BOT_UA_PATTERNS)

logger = logging.getLogger("snip.redirect")
redirect_bp = Blueprint('redirect', __name__)

@redirect_bp.route('/<code>', endpoint='redirect_link')
def redirect_link(code):
    conn = db.get_db()
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
            return redirect(target_url)

        # Re-validate custom ad URL at render time
        effective_ad_type = link['ad_type']
        effective_custom_url = link['custom_ad_url']
        if effective_ad_type == 'custom':
            owner_earnings = db.get_earnings(conn, link['owner_id'])
            if owner_earnings['custom_spend'] + 0.01 > owner_earnings['network_earnings']:
                effective_ad_type = 'network'
                effective_custom_url = ''
            elif not effective_custom_url or not core.is_safe_url(effective_custom_url):
                effective_ad_type = 'network'
                effective_custom_url = ''

        raw_media = link['custom_ad_media_type'] if 'custom_ad_media_type' in link.keys() else 'webpage'
        media_type = 'video' if raw_media == 'video' else 'webpage'

        safe_embed = None
        if media_type == 'video' and effective_custom_url:
            safe_embed = core.extract_youtube_embed(effective_custom_url)

        nonce = secrets.token_urlsafe(16)
        conn.execute('INSERT INTO ad_nonces (nonce, link_id) VALUES (?, ?)', (nonce, link['id']))
        conn.commit()

        serializer = get_ad_serializer()
        iat = int(time.time())
        client_binding = hashlib.sha256(f"{ip}|{user_agent}".encode('utf-8')).hexdigest()[:16]
        token = serializer.dumps({
            'link_id': link['id'],
            'nonce': nonce,
            'iat': iat,
            'client_binding': client_binding,
            'confirmed_safety': (request.args.get('confirm') == '1')
        })
        return render_template(
            'ad_interstitial.html',
            token=token,
            link=link,
            media_type=media_type,
            safe_embed=safe_embed,
            effective_ad_type=effective_ad_type,
            effective_custom_url=effective_custom_url
        )

    # Flow 3 — Direct redirect
    return redirect(target_url)

@redirect_bp.route('/continue/<token>', endpoint='continue_ad')
def continue_ad(token):
    serializer = get_ad_serializer()
    try:
        data = serializer.loads(token, max_age=120)
    except SignatureExpired:
        return render_template('expired.html', reason="Ad transit countdown expired. Please refresh the short link."), 400
    except BadSignature:
        abort(404)

    iat = data.get('iat', 0)
    ad_min_sec = float(os.environ.get('AD_MIN_SECONDS', 10))
    elapsed = time.time() - iat
    if elapsed < (ad_min_sec - 1.0):
        return render_template('expired.html', reason="Ad transit countdown was not completed."), 400

    client_ip = request.remote_addr or 'unknown'
    client_ua = request.headers.get('User-Agent', '')
    curr_binding = hashlib.sha256(f"{client_ip}|{client_ua}".encode('utf-8')).hexdigest()[:16]
    if not hmac.compare_digest(data.get('client_binding', ''), curr_binding):
        return render_template('403.html', reason="Security token validation failure: bound to another client."), 403

    nonce = data.get('nonce')
    link_id = data.get('link_id')

    conn = db.get_db()
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

    if link['expires_at']:
        try:
            expiry = _parse_link_expiry(link['expires_at'])
            if expiry and datetime.now(timezone.utc) >= expiry:
                conn.rollback()
                return render_template('expired.html', reason="Link has expired."), 410
        except (ValueError, TypeError):
            pass

    if link['safety_status'] == 'malicious' and not data.get('confirmed_safety'):
        conn.rollback()
        return render_template('warning.html', code=link['code'])

    target_url = link['original_url']
    if not core.validate_url_at_redirect(target_url):
        conn.rollback()
        abort(403)

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

@redirect_bp.route('/preview/<code>.jpg', endpoint='preview_image')
def preview_image(code):
    """Serves the locally saved website snapshot securely."""
    if not re.fullmatch(r'^[A-Za-z0-9_-]{1,30}$', code):
        abort(404)

    conn = db.get_db()
    link = conn.execute('SELECT id, original_url FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
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
        core.capture_screenshot(code, link['original_url'], db.DATA_DIR)
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

import re
import math
from flask import (Blueprint, request, render_template, redirect,
                   url_for, session, abort, flash, jsonify, current_app)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import SignatureExpired, BadSignature

import db
import core
import mailer
import otp
from mailer import MailStatus
from blueprints.helpers import (login_required, get_ip_hash, get_pending_serializer,
                                build_short_url, _delete_screenshot_file, _clean_ad_config)

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard', endpoint='dashboard')
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
    
    total_clicks_row = conn.execute('''
        SELECT COUNT(clicks.id) as tc 
        FROM clicks 
        JOIN links ON clicks.link_id = links.id 
        WHERE links.owner_id = ?
    ''', (uid,)).fetchone()
    total_clicks = total_clicks_row['tc'] if total_clicks_row else 0

    return render_template('dashboard.html',
                           links=links,
                           earnings=earnings_data['earnings'],
                           network_earnings=earnings_data['network_earnings'],
                           custom_spend=earnings_data['custom_spend'],
                           total_clicks=total_clicks,
                           page=page,
                           total_pages=total_pages,
                           total_links=total_links)

@dashboard_bp.route('/dashboard/live-stats', endpoint='dashboard_live_stats')
@login_required
def dashboard_live_stats():
    conn = db.get_db()
    uid = session['user_id']

    since = request.args.get('since', type=int)
    
    total_clicks_row = conn.execute('''
        SELECT COUNT(clicks.id) as tc 
        FROM clicks 
        JOIN links ON clicks.link_id = links.id 
        WHERE links.owner_id = ?
    ''', (uid,)).fetchone()
    total_clicks = total_clicks_row['tc'] if total_clicks_row else 0

    if since:
        links = conn.execute('''
            SELECT links.code, COUNT(clicks.id) AS click_count
            FROM links
            LEFT JOIN clicks ON clicks.link_id = links.id
            WHERE links.owner_id = ? 
              AND links.id IN (
                  SELECT DISTINCT link_id FROM clicks WHERE timestamp >= datetime(?, 'unixepoch')
              )
            GROUP BY links.id
        ''', (uid, since)).fetchall()
    else:
        links = conn.execute('''
            SELECT links.code, COUNT(clicks.id) AS click_count
            FROM links
            LEFT JOIN clicks ON clicks.link_id = links.id
            WHERE links.owner_id = ?
            GROUP BY links.id
        ''', (uid,)).fetchall()

    earnings_data = db.get_earnings(conn, uid)

    return jsonify({
        'earnings': earnings_data['earnings'],
        'earnings_formatted': earnings_data['earnings_formatted'],
        'network_earnings': earnings_data['network_earnings'],
        'custom_spend': earnings_data['custom_spend'],
        'total_clicks': total_clicks,
        'links': [{'code': row['code'], 'clicks': row['click_count']} for row in links]
    })

@dashboard_bp.route('/dashboard/account', endpoint='dashboard_account')
@login_required
def dashboard_account():
    conn = db.get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('account.html', user=user)

@dashboard_bp.route('/dashboard/account/change-password', methods=['POST'], endpoint='dashboard_account_change_password')
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

@dashboard_bp.route('/dashboard/account/regenerate-api-key', methods=['POST'], endpoint='dashboard_account_regenerate_api_key')
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

@dashboard_bp.route('/dashboard/account/change-email', methods=['POST'], endpoint='dashboard_account_change_email')
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

    pending_serializer = get_pending_serializer()

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
        conn, current_app.secret_key, email_normalized, new_email, 'change_email',
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

@dashboard_bp.route('/dashboard/account/verify-email-change', methods=['GET', 'POST'], endpoint='dashboard_verify_email_change')
@login_required
def dashboard_verify_email_change():
    pending_raw = session.get('pending_email_change')
    if not pending_raw:
        flash('No email change in progress.', 'error')
        return redirect(url_for('dashboard_account'))

    pending_serializer = get_pending_serializer()
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

        ok, res = otp.verify_otp(conn, current_app.secret_key, data['email_normalized'], 'change_email', code)
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

@dashboard_bp.route('/dashboard/account/resend-email-change', methods=['POST'], endpoint='dashboard_account_resend_email_change')
@login_required
def dashboard_account_resend_email_change():
    pending_raw = session.get('pending_email_change')
    if not pending_raw:
        flash('No email change in progress.', 'error')
        return redirect(url_for('dashboard_account'))

    pending_serializer = get_pending_serializer()
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
        conn, current_app.secret_key, data['email_normalized'], data['new_email'], 'change_email',
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

@dashboard_bp.route('/dashboard/account/logout-all', methods=['POST'], endpoint='dashboard_account_logout_all')
@login_required
def dashboard_account_logout_all():
    conn = db.get_db()
    conn.execute('UPDATE users SET session_version = session_version + 1 WHERE id = ?', (session['user_id'],))
    conn.commit()
    session.clear()
    flash('You have been logged out of all active sessions.', 'info')
    return redirect(url_for('login'))

@dashboard_bp.route('/dashboard/delete/<code>', methods=['POST'], endpoint='dashboard_delete')
@login_required
def dashboard_delete(code):
    """Session-authenticated delete for the web UI."""
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != session['user_id']:
        return jsonify({'error': 'Forbidden'}), 403

    conn.execute('DELETE FROM links WHERE code = ? COLLATE NOCASE', (code,))
    conn.commit()
    _delete_screenshot_file(code)
    return jsonify({'message': 'Deleted'}), 200

@dashboard_bp.route('/dashboard/toggle-ads/<code>', methods=['POST'], endpoint='dashboard_toggle_ads')
@login_required
def dashboard_toggle_ads(code):
    """Toggle ads monetization on/off for a link."""
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
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

    conn.execute('UPDATE links SET ads_enabled = ? WHERE code = ? COLLATE NOCASE', (new_val, code))
    conn.commit()
    return jsonify({'message': 'Updated', 'ads_enabled': bool(new_val)}), 200

@dashboard_bp.route('/dashboard/configure-ad/<code>', methods=['POST'], endpoint='dashboard_configure_ad')
@login_required
def dashboard_configure_ad(code):
    """Configure ad mode (network vs custom) and ad creative details for a link."""
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
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
        WHERE code = ? COLLATE NOCASE
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

@dashboard_bp.route('/dashboard/qr/<code>', endpoint='dashboard_qr')
@login_required
def dashboard_qr(code):
    if not re.fullmatch(r'^[A-Za-z0-9_-]{1,30}$', code):
        abort(404)
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
    if not link:
        abort(404)
    if link['owner_id'] != session['user_id']:
        flash('You can only manage your own links.', 'error')
        return redirect(url_for('dashboard'))
    short_url = build_short_url(code)
    return render_template('qr.html', link=link, short_url=short_url)

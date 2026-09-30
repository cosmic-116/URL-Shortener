import json
import secrets
import sqlite3
from flask import (Blueprint, request, render_template, redirect,
                   url_for, session, abort, flash, current_app)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import SignatureExpired, BadSignature

import db
import core
import mailer
import otp
from mailer import MailStatus
from blueprints.helpers import (DUMMY_PW_HASH, get_ip_hash, get_pending_serializer)

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'], endpoint='register')
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

        pending_serializer = get_pending_serializer()

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
            conn, current_app.secret_key, email_normalized, email, 'register',
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

@auth_bp.route('/register/verify', methods=['GET', 'POST'], endpoint='register_verify')
def register_verify():
    pending_raw = session.get('pending_register')
    if not pending_raw:
        flash('No registration in progress. Please register first.', 'error')
        return redirect(url_for('register'))

    pending_serializer = get_pending_serializer()
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

        ok, res = otp.verify_otp(conn, current_app.secret_key, data['email_normalized'], 'register', code)
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

        try:
            conn.execute('''
                INSERT INTO users (username, password_hash, api_key_hash, email, email_normalized, email_verified_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (username, pwhash, hashed_key, res['email_display'], data['email_normalized']))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            flash('This username was claimed while completing registration. Please register with a different username.', 'error')
            return redirect(url_for('register'))

        user = conn.execute('SELECT id, username, session_version FROM users WHERE username = ? COLLATE NOCASE', (username,)).fetchone()
        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['session_version'] = user['session_version']
        session['csrf_token'] = secrets.token_hex(32)

        return render_template('register_success.html', api_key=plaintext_key, username=user['username'])

    return render_template('verify_email.html', email=data['email'], resend_url='/register/resend', cancel_url='/register')

@auth_bp.route('/register/resend', methods=['POST'], endpoint='register_resend')
def register_resend():
    pending_raw = session.get('pending_register')
    if not pending_raw:
        flash('No registration in progress. Please register first.', 'error')
        return redirect(url_for('register'))

    pending_serializer = get_pending_serializer()
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
        conn, current_app.secret_key, data['email_normalized'], data['email'], 'register',
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

@auth_bp.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if core.is_rate_limited(f"login_ip:{ip}", max_requests=10, window_seconds=300):
            return render_template('429.html'), 429

        identifier = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if core.is_rate_limited(f"login_fail_user:{ip}:{identifier.lower()}", max_requests=5, window_seconds=900, record=False):
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

@auth_bp.route('/forgot-password', methods=['GET', 'POST'], endpoint='forgot_password')
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
                conn, current_app.secret_key, email_normalized, email, 'reset',
                user_id=user['id'], ip_hash=ip_hash
            )
            mailer.send_password_reset_otp(email, code)
        else:
            otp.create_otp(conn, current_app.secret_key, email_normalized, email, 'reset', user_id=None, ip_hash=ip_hash)

        pending_serializer = get_pending_serializer()
        session['pending_reset'] = pending_serializer.dumps({
            'email': email,
            'email_normalized': email_normalized
        })
        flash('If a verified account exists for this email, a 6-digit recovery code has been sent.', 'info')
        return redirect(url_for('reset_password'))

    return render_template('forgot_password.html')

@auth_bp.route('/reset-password', methods=['GET', 'POST'], endpoint='reset_password')
def reset_password():
    pending_raw = session.get('pending_reset')
    if not pending_raw:
        flash('No password reset in progress. Please request a code first.', 'error')
        return redirect(url_for('forgot_password'))

    pending_serializer = get_pending_serializer()
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
        ok, res = otp.verify_otp(conn, current_app.secret_key, data['email_normalized'], 'reset', code)
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

@auth_bp.route('/reset-password/resend', methods=['POST'], endpoint='reset_password_resend')
def reset_password_resend():
    pending_raw = session.get('pending_reset')
    if not pending_raw:
        flash('No password reset in progress.', 'error')
        return redirect(url_for('forgot_password'))

    pending_serializer = get_pending_serializer()
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
            conn, current_app.secret_key, data['email_normalized'], data['email'], 'reset',
            user_id=user['id'], ip_hash=ip_hash
        )
        mailer.send_password_reset_otp(data['email'], code)
    else:
        otp.create_otp(conn, current_app.secret_key, data['email_normalized'], data['email'], 'reset', user_id=None, ip_hash=ip_hash)

    flash('If eligible, a new recovery code has been sent.', 'info')
    return redirect(url_for('reset_password'))

@auth_bp.route('/logout', methods=['GET', 'POST'], endpoint='logout')
def logout():
    if request.method != 'POST':
        abort(405)
    session.clear()
    return redirect(url_for('index'))

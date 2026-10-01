import secrets
import hashlib
import hmac
import logging
from datetime import datetime, timezone, timedelta

def _parse_timestamp(ts_str):
    if not ts_str:
        raise ValueError("Timestamp string cannot be empty")
    ts_str = ts_str.replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(ts_str)
    except ValueError:
        dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

logger = logging.getLogger("snip.otp")

OTP_EXPIRY_MINUTES = 10
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
MAX_OTPS_PER_EMAIL_HOUR = 3
MAX_OTPS_PER_IP_HOUR = 10

def get_otp_key(secret_key):
    """Derives HMAC secret key isolated for OTPs."""
    return hashlib.sha256(secret_key.encode('utf-8') + b"|otp").digest()

def hash_otp_code(secret_key, email_normalized, purpose, code):
    """Computes HMAC-SHA256 digest of normalized email, purpose, and code."""
    key = get_otp_key(secret_key)
    msg = f"{email_normalized}|{purpose}|{code}".encode('utf-8')
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def check_otp_rate_limits(conn, email_normalized, purpose, ip_hash):
    """
    Validates resend cooldown, per-email hourly cap, and per-IP hourly cap.
    Returns (ok: bool, error_message: str, cooldown_remaining: int).
    """
    now_utc = datetime.now(timezone.utc)
    one_hour_ago = (now_utc - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')

    # 1. Cooldown check: most recent active or unconsumed OTP for this (email, purpose)
    recent = conn.execute('''
        SELECT created_at FROM email_otps
        WHERE email_normalized = ? AND purpose = ?
        ORDER BY id DESC LIMIT 1
    ''', (email_normalized, purpose)).fetchone()

    if recent and recent['created_at']:
        try:
            created_dt = _parse_timestamp(recent['created_at'])
            elapsed = (now_utc - created_dt).total_seconds()
            if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
                remaining = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
                return False, f"Please wait {remaining} seconds before requesting a new code.", remaining
        except Exception as e:
            logger.debug("Error parsing OTP created_at: %s", e)

    # 2. Hourly cap per (email, purpose): max 3
    email_count_row = conn.execute('''
        SELECT COUNT(*) as cnt FROM email_otps
        WHERE email_normalized = ? AND purpose = ? AND created_at >= ?
    ''', (email_normalized, purpose, one_hour_ago)).fetchone()
    email_count = email_count_row['cnt'] if email_count_row else 0
    if email_count >= MAX_OTPS_PER_EMAIL_HOUR:
        return False, "Too many verification codes requested for this email. Please try again in an hour.", 0

    # 3. Hourly cap per IP: max 10
    if ip_hash:
        ip_count_row = conn.execute('''
            SELECT COUNT(*) as cnt FROM email_otps
            WHERE ip_hash = ? AND created_at >= ?
        ''', (ip_hash, one_hour_ago)).fetchone()
        ip_count = ip_count_row['cnt'] if ip_count_row else 0
        if ip_count >= MAX_OTPS_PER_IP_HOUR:
            return False, "Too many verification requests from your network. Please try again in an hour.", 0

    return True, "", 0

def create_otp(conn, secret_key, email_normalized, email_display, purpose, user_id=None, pending_payload=None, ip_hash=None):
    """
    Generates a secure 6-digit OTP, marks older unconsumed OTPs consumed,
    and atomically inserts the new HMAC hash.
    Returns (code: str, expires_at_str: str).
    """
    # 6-digit random code
    code = f"{secrets.randbelow(1_000_000):06d}"
    code_hash = hash_otp_code(secret_key, email_normalized, purpose, code)

    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(minutes=OTP_EXPIRY_MINUTES)
    expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')

    # Atomic: consume any existing unconsumed OTPs for same email & purpose
    conn.execute('''
        UPDATE email_otps 
        SET consumed_at = CURRENT_TIMESTAMP, pending_payload = NULL
        WHERE email_normalized = ? AND purpose = ? AND consumed_at IS NULL
    ''', (email_normalized, purpose))

    conn.execute('''
        INSERT INTO email_otps (
            email_normalized, email_display, purpose, code_hash,
            user_id, pending_payload, expires_at, ip_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (email_normalized, email_display, purpose, code_hash, user_id, pending_payload, expires_at_str, ip_hash))
    conn.commit()

    return code, expires_at_str

def verify_otp(conn, secret_key, email_normalized, purpose, code_submitted):
    """
    Atomically verifies a submitted OTP code.
    Increments and commits attempts before comparison (Refinement 7).
    Clears pending_payload on successful consumption (Refinement 9).
    Returns (success: bool, payload_or_error: dict|str).
    """
    if not code_submitted or not isinstance(code_submitted, str):
        return False, "Verification code is required."
    code_submitted = code_submitted.strip()

    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute('''
        SELECT * FROM email_otps
        WHERE email_normalized = ? AND purpose = ? AND consumed_at IS NULL
        ORDER BY id DESC LIMIT 1
    ''', (email_normalized, purpose)).fetchone()

    if not row:
        conn.commit()
        return False, "No active verification code found. Please request a new one."

    # Parse expiration
    try:
        exp_dt = _parse_timestamp(row['expires_at'])
    except Exception:
        conn.commit()
        return False, "Malformed code expiration timestamp."

    now_utc = datetime.now(timezone.utc)
    if now_utc > exp_dt:
        conn.commit()
        return False, "Verification code has expired. Please request a new one."

    if row['attempts'] >= OTP_MAX_ATTEMPTS:
        conn.commit()
        return False, "Too many incorrect attempts. This code is no longer valid. Please request a new one."

    # Atomically increment attempts and COMMIT IMMEDIATELY (Refinement 7)
    new_attempts = row['attempts'] + 1
    conn.execute('UPDATE email_otps SET attempts = ? WHERE id = ?', (new_attempts, row['id']))
    conn.commit()

    expected_hash = hash_otp_code(secret_key, email_normalized, purpose, code_submitted)
    if not hmac.compare_digest(row['code_hash'], expected_hash):
        remaining_attempts = OTP_MAX_ATTEMPTS - new_attempts
        if remaining_attempts <= 0:
            return False, "Too many incorrect attempts. This code is no longer valid. Please request a new one."
        return False, f"Invalid verification code. {remaining_attempts} attempt{'s' if remaining_attempts != 1 else ''} remaining."

    # Code matched! Consume OTP and clear pending_payload (Refinement 9)
    conn.execute('''
        UPDATE email_otps 
        SET consumed_at = CURRENT_TIMESTAMP, pending_payload = NULL 
        WHERE id = ?
    ''', (row['id'],))
    conn.commit()

    return True, dict(row)

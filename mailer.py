import os
import ssl
import time
import socket
import smtplib
import email.message
import email.utils
import logging
import sqlite3
import concurrent.futures
from enum import Enum

logger = logging.getLogger("snip.mailer")

class MailStatus(Enum):
    SENT = "sent"
    QUEUED = "queued"
    CAP_REACHED = "cap_reached"
    FAILED = "failed"

    def __bool__(self):
        return self in (MailStatus.SENT, MailStatus.QUEUED)

# Test outbox
OUTBOX = []

# Module-level ThreadPoolExecutor with bounded capacity
_MAX_MAIL_BACKLOG = 50
_mail_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="snip-mailer")

def clear_outbox():
    """Clears the in-memory test outbox."""
    global OUTBOX
    OUTBOX.clear()

def mask_email(addr):
    """Masks email address for structured logging (e.g. a***@domain.com)."""
    if not addr or not isinstance(addr, str) or '@' not in addr:
        return "invalid@masked"
    local, domain = addr.split('@', 1)
    if len(local) <= 1:
        masked_local = "*"
    elif len(local) == 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "***"
    return f"{masked_local}@{domain}"

def get_mail_db():
    """Opens a dedicated SQLite connection with busy timeout for mailer operations."""
    import db
    conn = sqlite3.connect(db.DATABASE, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def check_and_increment_mail_counters():
    """
    Checks per-minute, per-hour, and per-day send caps in SQLite.
    Returns True if allowed (and increments counters atomically), False if any cap reached.
    """
    max_min = int(os.environ.get('MAIL_MAX_PER_MINUTE', 25))
    max_hour = int(os.environ.get('MAIL_MAX_PER_HOUR', 90))
    max_day = int(os.environ.get('MAIL_MAX_PER_DAY', 250))

    now = time.gmtime()
    b_min = time.strftime("m:%Y-%m-%d-%H-%M", now)
    b_hour = time.strftime("h:%Y-%m-%d-%H", now)
    b_day = time.strftime("d:%Y-%m-%d", now)

    conn = get_mail_db()
    try:
        conn.execute("BEGIN IMMEDIATE")

        rows = conn.execute(
            "SELECT bucket, count FROM mail_counters WHERE bucket IN (?, ?, ?)",
            (b_min, b_hour, b_day)
        ).fetchall()
        counts = {r['bucket']: r['count'] for r in rows}

        if counts.get(b_min, 0) >= max_min:
            logger.warning("Mail cap reached: per-minute limit (%d)", max_min)
            conn.rollback()
            return False

        if counts.get(b_hour, 0) >= max_hour:
            logger.warning("Mail cap reached: per-hour limit (%d)", max_hour)
            conn.rollback()
            return False

        if counts.get(b_day, 0) >= max_day:
            logger.warning("Mail cap reached: per-day limit (%d)", max_day)
            conn.rollback()
            return False

        # Atomically increment all three buckets
        for b in (b_min, b_hour, b_day):
            conn.execute(
                "INSERT INTO mail_counters (bucket, count) VALUES (?, 1) "
                "ON CONFLICT(bucket) DO UPDATE SET count = count + 1",
                (b,)
            )
        conn.commit()
        return True
    except Exception as e:
        logger.error("Error updating mail counters: %s", type(e).__name__)
        conn.rollback()
        return False
    finally:
        conn.close()

def verify_mail_config():
    """
    Validates required email configuration at startup.
    Fails fast in production mode if required variables are missing.
    Never prints credentials or secret values.
    """
    backend = os.environ.get('MAIL_BACKEND', 'acs').lower()
    is_debug = os.environ.get('FLASK_DEBUG') == '1' or os.environ.get('FLASK_ENV') == 'development'
    is_testing = os.environ.get('TESTING') == '1'

    if is_testing or is_debug:
        return

    if backend == 'console':
        raise RuntimeError("FATAL: MAIL_BACKEND='console' is not permitted in production.")

    if backend in ('acs', 'smtp'):
        from_val = os.environ.get('MAIL_FROM') or os.environ.get('SMTP_FROM')
        required = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD']
        missing = [var for var in required if not os.environ.get(var)]
        if not from_val:
            missing.append('SMTP_FROM')
        if missing:
            raise RuntimeError(
                f"FATAL: Missing required email configuration environment variables: {', '.join(missing)}. "
                "Refusing to start."
            )

def _build_email_message(to, subject, text_body, html_body=None):
    """
    Constructs an EmailMessage instance and enforces strict CR/LF sanitization.
    Raises ValueError on any CR/LF injection attempt.
    """
    for val, name in [(to, "to"), (subject, "subject")]:
        if not val or not isinstance(val, str) or '\r' in val or '\n' in val:
            raise ValueError(f"Header '{name}' contains disallowed CR/LF line breaks or is invalid")

    from_addr = os.environ.get('MAIL_FROM') or os.environ.get('SMTP_FROM') or 'DoNotReply@localhost'
    if '\r' in from_addr or '\n' in from_addr:
        raise ValueError("Header 'from' contains disallowed CR/LF line breaks")

    from_name = os.environ.get('MAIL_FROM_NAME', 'Snip')
    if '\r' in from_name or '\n' in from_name:
        raise ValueError("MAIL_FROM_NAME contains disallowed CR/LF line breaks")

    msg = email.message.EmailMessage()
    msg['To'] = to
    msg['From'] = email.utils.formataddr((from_name, from_addr)) if from_name else from_addr
    msg['Subject'] = subject
    msg['Date'] = email.utils.formatdate(localtime=True)

    # Domain for Message-ID
    from_domain = from_addr.split('@')[-1] if '@' in from_addr else 'localhost'
    msg['Message-ID'] = email.utils.make_msgid(domain=from_domain)
    msg['Auto-Submitted'] = 'auto-generated'
    msg['X-Auto-Response-Suppress'] = 'All'

    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype='html')

    return msg

def _dispatch_smtp(msg, to_masked):
    """
    Transmits email via STARTTLS SMTP with single retry on 4xx/timeout.
    Never retries 5xx. Logs only masked recipient, error type, and SMTP code.
    """
    backend = os.environ.get('MAIL_BACKEND', 'acs').lower()
    default_host = 'smtp.azurecomm.net' if backend == 'acs' else 'localhost'
    host = os.environ.get('SMTP_HOST', default_host)
    port = int(os.environ.get('SMTP_PORT', 587))
    user = os.environ.get('SMTP_USER', '')
    password = os.environ.get('SMTP_PASSWORD', '')

    def _attempt_send():
        context = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if user and password:
                server.login(user, password)
            server.send_message(msg)

    # Attempt 1
    try:
        _attempt_send()
        return True
    except smtplib.SMTPResponseException as e:
        code = getattr(e, 'smtp_code', 0)
        if 400 <= code < 500:
            logger.warning("SMTP 4xx transient error (%d) sending to %s. Retrying in 2s...", code, to_masked)
            time.sleep(2.0)
            try:
                _attempt_send()
                return True
            except Exception as retry_e:
                logger.error("SMTP retry failed: type=%s code=%s recipient=%s", type(retry_e).__name__, getattr(retry_e, 'smtp_code', 'none'), to_masked)
                return False
        else:
            logger.error("SMTP permanent error: type=%s code=%s recipient=%s", type(e).__name__, code, to_masked)
            return False
    except (socket.timeout, TimeoutError, ConnectionError, OSError) as e:
        logger.warning("Transient network error (%s) sending to %s. Retrying in 2s...", type(e).__name__, to_masked)
        time.sleep(2.0)
        try:
            _attempt_send()
            return True
        except Exception as retry_e:
            logger.error("SMTP network retry failed: type=%s recipient=%s", type(retry_e).__name__, to_masked)
            return False
    except Exception as e:
        logger.error("SMTP transmission error: type=%s recipient=%s", type(e).__name__, to_masked)
        return False

def _transmit_task(msg, to_masked):
    """Worker task executed in background thread."""
    backend = os.environ.get('MAIL_BACKEND', 'acs').lower()
    is_debug = os.environ.get('FLASK_DEBUG') == '1'
    is_testing = os.environ.get('TESTING') == '1'

    if backend == 'test' or is_testing:
        OUTBOX.append(msg)
        return True

    if backend == 'console':
        if is_debug:
            print(f"\n--- [MAIL CONSOLE] To: {msg['To']} | Subject: {msg['Subject']} ---")
            body = msg.get_body(preferencelist=('plain', 'html'))
            content = body.get_content() if body else msg.as_string()
            print(content)
            print("--- [END MAIL] ---\n")
            return True
        else:
            logger.error("Refusing console email output in non-debug mode for %s", to_masked)
            return False

    return _dispatch_smtp(msg, to_masked)

def send_mail(to, subject, text_body, html_body=None, sync=False):
    """
    Submits an email for transmission. Never raises exceptions to caller.
    Enforces persistent SQLite quotas across Gunicorn workers.
    Returns MailStatus (SENT, QUEUED, CAP_REACHED, FAILED).
    """
    to_masked = mask_email(to)

    # 1. Message building and CR/LF injection check
    try:
        msg = _build_email_message(to, subject, text_body, html_body)
    except Exception as e:
        logger.error("Email construction rejected: type=%s recipient=%s", type(e).__name__, to_masked)
        return MailStatus.FAILED

    # 2. Check and atomically increment persistent SQLite mail counters
    if not check_and_increment_mail_counters():
        return MailStatus.CAP_REACHED

    backend = os.environ.get('MAIL_BACKEND', 'acs').lower()
    is_testing = os.environ.get('TESTING') == '1'

    # In test mode or when sync is requested, execute synchronously
    if backend == 'test' or is_testing:
        OUTBOX.append(msg)
        return MailStatus.SENT

    if sync:
        ok = _transmit_task(msg, to_masked)
        return MailStatus.SENT if ok else MailStatus.FAILED

    # 3. Asynchronous queue dispatch with bounded backlog
    try:
        # Check executor backlog
        if _mail_executor._work_queue.qsize() > _MAX_MAIL_BACKLOG:
            logger.error("Mailer backlog capacity exceeded (>%d). Dropping message to %s", _MAX_MAIL_BACKLOG, to_masked)
            return MailStatus.FAILED

        _mail_executor.submit(_transmit_task, msg, to_masked)
        return MailStatus.QUEUED
    except Exception as e:
        logger.error("Failed to queue mail task: type=%s recipient=%s", type(e).__name__, to_masked)
        return MailStatus.FAILED


# ── High-Level Email Templating Helpers ─────────────────────

def _render_email_template(template_name, context, fallback_html):
    """Renders Jinja email template from templates/emails/ if in app context, else falls back."""
    try:
        from flask import render_template, has_app_context
        if has_app_context():
            return render_template(f"emails/{template_name}", **context)
    except Exception as e:
        logger.debug("Template render fallback: %s", e)
    return fallback_html

def send_registration_otp(to, code, expires_minutes=10, sync=False):
    """Sends 6-digit registration verification code."""
    subject = "Verify Your Snip Account"
    text = (
        f"Welcome to Snip!\n\n"
        f"Your 6-digit verification code is: {code}\n\n"
        f"This code will expire in {expires_minutes} minutes.\n"
        f"If you did not request this account, you can safely ignore this email.\n"
    )
    fallback_html = text.replace('\n', '<br>')
    html = _render_email_template("registration_otp.html", {"code": code, "expires_minutes": expires_minutes}, fallback_html)
    return send_mail(to, subject, text, html_body=html, sync=sync)

def send_password_reset_otp(to, code, expires_minutes=10, sync=False):
    """Sends 6-digit password reset verification code."""
    subject = "Reset Your Snip Password"
    text = (
        f"Password Reset Request\n\n"
        f"Your 6-digit recovery code is: {code}\n\n"
        f"This code will expire in {expires_minutes} minutes.\n"
        f"If you did not request a password reset, your account is secure and you can safely ignore this email.\n"
    )
    fallback_html = text.replace('\n', '<br>')
    html = _render_email_template("password_reset_otp.html", {"code": code, "expires_minutes": expires_minutes}, fallback_html)
    return send_mail(to, subject, text, html_body=html, sync=sync)

def send_change_email_otp(to, code, expires_minutes=10, sync=False):
    """Sends 6-digit code to verify new email address."""
    subject = "Verify New Snip Email Address"
    text = (
        f"Email Change Request\n\n"
        f"Your 6-digit verification code is: {code}\n\n"
        f"This code will expire in {expires_minutes} minutes.\n"
        f"If you did not initiate this change, please ignore this email.\n"
    )
    fallback_html = text.replace('\n', '<br>')
    html = _render_email_template("change_email_otp.html", {"code": code, "expires_minutes": expires_minutes}, fallback_html)
    return send_mail(to, subject, text, html_body=html, sync=sync)

def send_security_alert(to, subject, message, sync=False):
    """Sends security notification email for account modifications."""
    text = (
        f"Security Notice\n\n"
        f"{message}\n\n"
        f"If you did not make this change, please secure your account immediately.\n"
    )
    fallback_html = text.replace('\n', '<br>')
    html = _render_email_template("security_alert.html", {"subject": subject, "message": message}, fallback_html)
    return send_mail(to, subject, text, html_body=html, sync=sync)


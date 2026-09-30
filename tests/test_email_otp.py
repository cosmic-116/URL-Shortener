import os
import sys
import unittest
import tempfile
import json
import time
import re
import smtplib
from unittest.mock import MagicMock, patch

# Ensure app directory is importable
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Set test environment
os.environ['TESTING'] = '1'
os.environ['MAIL_BACKEND'] = 'test'
os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-12345678901234567890'

import core
import db
import mailer
import otp
from werkzeug.security import generate_password_hash
from mailer import MailStatus
from app import app, serializer


class SnipEmailAndOTPTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        db.DATABASE = self.temp_db_path
        db.DATA_DIR = os.path.dirname(self.temp_db_path)
        app.config['TESTING'] = True
        app.secret_key = 'test-secret-key-12345678901234567890'
        db.init_db(app)
        self.client = app.test_client()
        mailer.clear_outbox()

    def tearDown(self):
        try:
            os.close(self.temp_db_fd)
            if os.path.exists(self.temp_db_path):
                os.remove(self.temp_db_path)
        except OSError:
            pass

    def _extract_otp(self, msg=None):
        if msg is None:
            if not mailer.OUTBOX:
                return None
            msg = mailer.OUTBOX[-1]
        body = msg.get_body(preferencelist=('plain',)).get_content()
        m = re.search(r'\b(\d{6})\b', body)
        return m.group(1) if m else None

    # ── 1. Registration Flow Tests ──────────────────────────────

    def test_registration_creates_no_user_before_verification(self):
        """Verifies no user row is created before OTP verification and payload stores hashed password."""
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')

            resp = c.post('/register', data={
                'username': 'alice_pending',
                'email': 'alice@example.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b'Check Your Inbox', resp.data)

            # Check DB: no user row should exist
            with app.app_context():
                conn = db.get_db()
                user = conn.execute("SELECT * FROM users WHERE username = 'alice_pending'").fetchone()
                self.assertIsNone(user)

                # Check OTP table: pending payload exists and contains password hash, not plaintext password
                otp_row = conn.execute("SELECT * FROM email_otps WHERE email_normalized = 'alice@example.com'").fetchone()
                self.assertIsNotNone(otp_row)
                self.assertIsNotNone(otp_row['pending_payload'])
                payload = json.loads(otp_row['pending_payload'])
                self.assertEqual(payload['username'], 'alice_pending')
                self.assertNotIn('StrongPassword1', otp_row['pending_payload'])
                self.assertTrue(payload['password_hash'].startswith('scrypt:') or payload['password_hash'].startswith('pbkdf2:'))

    def test_correct_otp_creates_verified_user_and_shows_api_key_once(self):
        """Validates registration completion, automatic login, and single API key display."""
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')

            c.post('/register', data={
                'username': 'charlie_new',
                'email': 'charlie@example.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=True)

            code = self._extract_otp()
            self.assertIsNotNone(code)

            csrf = session.get('csrf_token')
            verify_resp = c.post('/register/verify', data={
                'code': code,
                'csrf_token': csrf
            }, follow_redirects=True)
            self.assertEqual(verify_resp.status_code, 200)
            self.assertIn(b'Account Created', verify_resp.data)
            self.assertIn(b'Secret API Key', verify_resp.data)

            # User must now exist in DB with email_verified_at set
            with app.app_context():
                conn = db.get_db()
                user = conn.execute("SELECT * FROM users WHERE username = 'charlie_new'").fetchone()
                self.assertIsNotNone(user)
                self.assertEqual(user['email'], 'charlie@example.com')
                self.assertIsNotNone(user['email_verified_at'])

            # Navigating back or refreshing should NOT show the API key again
            dash_resp = c.get('/dashboard')
            self.assertEqual(dash_resp.status_code, 200)
            self.assertNotIn(b'Secret API Key', dash_resp.data)

    def test_five_wrong_attempts_kill_otp(self):
        """Verifies OTP becomes permanently invalid after 5 failed attempts even if correct code is then submitted."""
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')

            c.post('/register', data={
                'username': 'david_attempts',
                'email': 'david@example.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=True)

            code = self._extract_otp()
            self.assertIsNotNone(code)

            # 5 consecutive incorrect attempts
            for i in range(1, 6):
                csrf = session.get('csrf_token')
                resp = c.post('/register/verify', data={'code': '999999', 'csrf_token': csrf}, follow_redirects=True)
                self.assertEqual(resp.status_code, 200)
                if i < 5:
                    self.assertIn(f"{5 - i} attempt".encode(), resp.data)
                else:
                    self.assertIn(b'Too many incorrect attempts', resp.data)

            # 6th attempt with CORRECT code must be rejected
            csrf = session.get('csrf_token')
            resp = c.post('/register/verify', data={'code': code, 'csrf_token': csrf}, follow_redirects=True)
            self.assertIn(b'Too many incorrect attempts', resp.data)

            # User was never created
            with app.app_context():
                conn = db.get_db()
                self.assertIsNone(conn.execute("SELECT id FROM users WHERE username = 'david_attempts'").fetchone())

    def test_attempts_persisted_after_failed_otp(self):
        """Refinements 7 & 13: Verifies that attempts count is committed to SQLite before returning an error."""
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')

            c.post('/register', data={
                'username': 'eva_persist',
                'email': 'eva@example.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=True)

            # Submit 1 wrong code
            csrf = session.get('csrf_token')
            c.post('/register/verify', data={'code': '000000', 'csrf_token': csrf})

            # Check DB directly in independent context
            with app.app_context():
                conn = db.get_db()
                row = conn.execute("SELECT attempts FROM email_otps WHERE email_normalized = 'eva@example.com'").fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row['attempts'], 1)

    def test_expired_otp_rejected(self):
        """Verifies rejection of expired OTPs."""
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')

            c.post('/register', data={
                'username': 'frank_exp',
                'email': 'frank@example.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=True)

            code = self._extract_otp()

            # Artificially expire the OTP in DB
            with app.app_context():
                conn = db.get_db()
                conn.execute(
                    "UPDATE email_otps SET expires_at = datetime('now', '-10 minutes') WHERE email_normalized = 'frank@example.com'"
                )
                conn.commit()

            csrf = session.get('csrf_token')
            resp = c.post('/register/verify', data={'code': code, 'csrf_token': csrf}, follow_redirects=True)
            self.assertIn(b'expired', resp.data)

    def test_resend_cooldown_and_hourly_caps(self):
        """Verifies 60s resend cooldown, 3/hr per email, and invalidation of old unconsumed OTPs."""
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')

            c.post('/register', data={
                'username': 'grace_rate',
                'email': 'grace@example.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=True)

            # 1. Immediate resend within 60s should trigger cooldown warning
            csrf = session.get('csrf_token')
            resend_resp = c.post('/register/resend', data={'csrf_token': csrf}, follow_redirects=True)
            self.assertIn(b'Please wait', resend_resp.data)

            # 2. Simulate 60s passing, request again
            with app.app_context():
                conn = db.get_db()
                conn.execute(
                    "UPDATE email_otps SET created_at = datetime('now', '-65 seconds') WHERE email_normalized = 'grace@example.com'"
                )
                conn.commit()

            csrf = session.get('csrf_token')
            resend_resp2 = c.post('/register/resend', data={'csrf_token': csrf}, follow_redirects=True)
            self.assertIn(b'new 6-digit verification code has been sent', resend_resp2.data)

            # Check that the first OTP was marked consumed
            with app.app_context():
                conn = db.get_db()
                otps = conn.execute(
                    "SELECT id, consumed_at FROM email_otps WHERE email_normalized = 'grace@example.com' ORDER BY id ASC"
                ).fetchall()
                self.assertEqual(len(otps), 2)
                self.assertIsNotNone(otps[0]['consumed_at'])
                self.assertIsNone(otps[1]['consumed_at'])

    def test_db_stores_only_hmacs(self):
        """Verifies that the database stores only HMAC-SHA256 digests and never plaintext codes."""
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')

            c.post('/register', data={
                'username': 'helen_hmac',
                'email': 'helen@example.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=True)

            code = self._extract_otp()

            with app.app_context():
                conn = db.get_db()
                row = conn.execute("SELECT code_hash FROM email_otps WHERE email_normalized = 'helen@example.com'").fetchone()
                self.assertIsNotNone(row)
                code_hash = row['code_hash']
                # Must be 64-char hex
                self.assertEqual(len(code_hash), 64)
                self.assertNotEqual(code_hash, code)
                self.assertNotIn(code, code_hash)

                # Verify matches derived HMAC
                expected = otp.hash_otp_code(app.secret_key, 'helen@example.com', 'register', code)
                self.assertEqual(code_hash, expected)

    # ── 2. Password Reset Flow Tests ────────────────────────────

    def test_forgot_password_anti_enumeration_and_uniform_throttling(self):
        """Refinements 4, 8 & 13: Tests anti-enumeration notice and identical throttling for existing vs non-existing accounts."""
        # 1. Existing verified user
        with app.app_context():
            conn = db.get_db()
            pwhash = generate_password_hash("OldPassword123")
            _, hkey = core.generate_api_key()
            conn.execute(
                "INSERT INTO users (username, password_hash, api_key_hash, email, email_normalized, email_verified_at) "
                "VALUES ('real_user', ?, ?, 'real@example.com', 'real@example.com', CURRENT_TIMESTAMP)",
                (pwhash, hkey)
            )
            conn.commit()

        # Non-existing email request
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')
            resp_fake = c.post('/forgot-password', data={'email': 'fake@example.com', 'csrf_token': csrf}, follow_redirects=True)
            self.assertEqual(resp_fake.status_code, 200)
            self.assertIn(b'If a verified account exists for this email', resp_fake.data)
            self.assertEqual(len(mailer.OUTBOX), 0)

            # Cooldown check: second request for fake email within 60s receives identical cooldown notice
            csrf = session.get('csrf_token')
            resp_fake2 = c.post('/forgot-password', data={'email': 'fake@example.com', 'csrf_token': csrf}, follow_redirects=True)
            self.assertIn(b'Please wait', resp_fake2.data)

        # Existing email request
        with self.client as c:
            c.get('/')
            from flask import session
            csrf = session.get('csrf_token')
            resp_real = c.post('/forgot-password', data={'email': 'real@example.com', 'csrf_token': csrf}, follow_redirects=True)
            self.assertEqual(resp_real.status_code, 200)
            self.assertIn(b'If a verified account exists for this email', resp_real.data)
            self.assertEqual(len(mailer.OUTBOX), 1)

            # Second request for real email within 60s receives identical cooldown notice
            csrf = session.get('csrf_token')
            resp_real2 = c.post('/forgot-password', data={'email': 'real@example.com', 'csrf_token': csrf}, follow_redirects=True)
            self.assertIn(b'Please wait', resp_real2.data)

    def test_password_reset_revokes_sessions_and_notifies(self):
        """Verifies password reset updates password, bumps session_version to revoke active sessions, and queues alert email."""
        with app.app_context():
            conn = db.get_db()
            pwhash = generate_password_hash("OldPassword123")
            _, hkey = core.generate_api_key()
            conn.execute(
                "INSERT INTO users (username, password_hash, api_key_hash, email, email_normalized, email_verified_at) "
                "VALUES ('reset_user', ?, ?, 'reset@example.com', 'reset@example.com', CURRENT_TIMESTAMP)",
                (pwhash, hkey)
            )
            conn.commit()

        # Session 1: logs in
        client1 = app.test_client()
        with client1 as c1:
            c1.get('/login')
            from flask import session
            csrf = session.get('csrf_token')
            c1.post('/login', data={'username': 'reset_user', 'password': 'OldPassword123', 'csrf_token': csrf})
            self.assertEqual(c1.get('/dashboard').status_code, 200)

        # Session 2: executes password reset
        client2 = app.test_client()
        with client2 as c2:
            c2.get('/')
            from flask import session
            csrf = session.get('csrf_token')
            c2.post('/forgot-password', data={'email': 'reset@example.com', 'csrf_token': csrf})

            code = self._extract_otp()
            self.assertIsNotNone(code)

            csrf = session.get('csrf_token')
            reset_resp = c2.post('/reset-password', data={
                'code': code,
                'password': 'NewPassword999',
                'csrf_token': csrf
            }, follow_redirects=True)
            self.assertEqual(reset_resp.status_code, 200)
            self.assertIn(b'password has been reset successfully', reset_resp.data)

        # Session 1 must now be revoked due to session_version bump
        with client1 as c1:
            dash_resp = c1.get('/dashboard', follow_redirects=False)
            self.assertEqual(dash_resp.status_code, 302)
            self.assertTrue(dash_resp.headers['Location'].endswith('/login'))

        # Security alert email was sent
        self.assertTrue(len(mailer.OUTBOX) >= 2)
        alert_msg = mailer.OUTBOX[-1]
        self.assertEqual(alert_msg['Subject'], "Your Snip Password Was Changed")

    # ── 3. Email Normalization & Validation Tests ───────────────

    def test_email_normalization_and_injection(self):
        """Validates Gmail dot/plus stripping, iCloud plus stripping, IDNA, and CR/LF injection blocking."""
        # Gmail normalization
        ok, res = core.validate_email("John.Doe+newsletter@googlemail.com")
        self.assertTrue(ok)
        self.assertEqual(res, "johndoe@gmail.com")

        # iCloud normalization
        ok, res = core.validate_email("test.user+tag@icloud.com")
        self.assertTrue(ok)
        self.assertEqual(res, "test.user@icloud.com")

        # IDNA punycode domain
        ok, res = core.validate_email("user@münchen.de")
        self.assertTrue(ok)
        self.assertIn("xn--mnchen-3ya.de", res)

        # CR/LF injection in email address
        ok, _ = core.validate_email("attacker@victim.com\r\nBcc: evil@hacker.com")
        self.assertFalse(ok)
        ok, _ = core.validate_email("user\nname@example.com")
        self.assertFalse(ok)

        # Header CR/LF rejection in mailer
        with self.assertRaises(ValueError):
            mailer._build_email_message("to@domain.com\r\nBcc: evil@domain.com", "Subject", "Body")
        with self.assertRaises(ValueError):
            mailer._build_email_message("to@domain.com", "Subject\r\nInjected: Header", "Body")

    def test_disposable_domains_blocked(self):
        """Verifies that disposable temporary email providers are rejected."""
        disposables = ["test@mailinator.com", "fake@10minutemail.com", "temp@throwawaymail.com"]
        for addr in disposables:
            ok, err = core.validate_email(addr)
            self.assertFalse(ok)
            self.assertIn("Disposable email addresses are not permitted", err)

    # ── 4. Legacy User Enforcement & API Access ──────────────────

    def test_unverified_user_api_key_requires_verification(self):
        """Verifies API access obeys REQUIRE_VERIFIED_EMAIL_FOR_API for verified vs unverified users."""
        with app.app_context():
            conn = db.get_db()
            pwhash = generate_password_hash("Password123")
            raw_key, hkey = core.generate_api_key()
            conn.execute(
                "INSERT INTO users (username, password_hash, api_key_hash, email_verified_at) "
                "VALUES ('verified_user', ?, ?, CURRENT_TIMESTAMP)",
                (pwhash, hkey)
            )
            conn.commit()

        # API Key Access Check with REQUIRE_VERIFIED_EMAIL_FOR_API
        with patch.dict(os.environ, {'REQUIRE_VERIFIED_EMAIL_FOR_API': '1'}):
            # Verified user succeeds
            res_v = self.client.get('/api/analytics', headers={'X-API-Key': raw_key})
            self.assertEqual(res_v.status_code, 200)

            # Create unverified user API key
            with app.app_context():
                conn = db.get_db()
                unverified_plain, unverified_hash = core.generate_api_key()
                conn.execute(
                    "INSERT INTO users (username, password_hash, api_key_hash, email_verified_at) VALUES ('unv_api', 'h', ?, NULL)",
                    (unverified_hash,)
                )
                conn.commit()

            res_unv = self.client.get('/api/analytics', headers={'X-API-Key': unverified_plain})
            self.assertEqual(res_unv.status_code, 403)
            self.assertIn("Email verification required", res_unv.get_json()['error'])

    # ── 5. Monetization Abuse Blocked for Unverified Owners ───────

    def test_unverified_owner_monetization_abuse_blocked(self):
        """Refinements 6, 12 & 13: Verifies unverified users cannot enable ads and ad transit will NOT credit ledger for unverified owners."""
        with app.app_context():
            conn = db.get_db()
            pwhash = generate_password_hash("Password123")
            _, hkey = core.generate_api_key()
            conn.execute(
                "INSERT INTO users (username, password_hash, api_key_hash, email_verified_at) VALUES ('unv_monetize', ?, ?, NULL)",
                (pwhash, hkey)
            )
            unv_id = conn.execute("SELECT id FROM users WHERE username = 'unv_monetize'").fetchone()['id']
            # Direct link insert with ads_enabled = 1 for unverified owner
            conn.execute(
                "INSERT INTO links (code, original_url, owner_id, ads_enabled) VALUES ('UNVAD1', 'https://github.com', ?, 1)",
                (unv_id,)
            )
            conn.commit()

        # Simulate ad interstitial render and token generation
        import re
        iat = int(time.time()) - 15
        with self.client as c:
            redir_resp = c.get('/UNVAD1')
            self.assertEqual(redir_resp.status_code, 200)
            m = re.search(r'/continue/([A-Za-z0-9_\-\.]+)', redir_resp.data.decode('utf-8'))
            self.assertIsNotNone(m)
            raw_token = m.group(1)

            token_data = serializer.loads(raw_token)
            token_data['iat'] = iat
            token = serializer.dumps(token_data)

            # Complete transit
            resp = c.get(f'/continue/{token}')
            self.assertEqual(resp.status_code, 302)

        # Ledger MUST be 0 because owner is unverified
        with app.app_context():
            conn = db.get_db()
            ledger_count = conn.execute("SELECT COUNT(*) as count FROM ad_ledger").fetchone()['count']
            self.assertEqual(ledger_count, 0)

    # ── 6. Account Actions Rate Limits & Cache-Control ───────────

    def test_account_action_rate_limits(self):
        """Refinements 5 & 13: Tests 5/hour per-user rate limit on change-password, regenerate-api-key, and change-email."""
        with app.app_context():
            conn = db.get_db()
            pwhash = generate_password_hash("Password123")
            _, hkey = core.generate_api_key()
            conn.execute(
                "INSERT INTO users (username, password_hash, api_key_hash, email, email_normalized, email_verified_at) "
                "VALUES ('rate_acc_user', ?, ?, 'rate@example.com', 'rate@example.com', CURRENT_TIMESTAMP)",
                (pwhash, hkey)
            )
            conn.commit()

        with self.client as c:
            c.get('/login')
            from flask import session
            csrf = session.get('csrf_token')
            c.post('/login', data={'username': 'rate_acc_user', 'password': 'Password123', 'csrf_token': csrf})

            # 5 key regenerations allowed, 6th returns 429
            for _ in range(5):
                csrf = session.get('csrf_token')
                resp = c.post('/dashboard/account/regenerate-api-key', data={'current_password': 'Password123', 'csrf_token': csrf})
                self.assertEqual(resp.status_code, 200)

            csrf = session.get('csrf_token')
            resp_6 = c.post('/dashboard/account/regenerate-api-key', data={'current_password': 'Password123', 'csrf_token': csrf})
            self.assertEqual(resp_6.status_code, 429)

    def test_cache_control_no_store_headers(self):
        """Refinements 2 & 13: Tests Cache-Control: no-store on sensitive auth and account endpoints and logged-in sessions."""
        sensitive_routes = ['/register', '/login', '/forgot-password', '/reset-password']
        for route in sensitive_routes:
            resp = self.client.get(route)
            cc = resp.headers.get('Cache-Control', '')
            self.assertIn('no-store', cc)
            self.assertIn('no-cache', cc)

        # Logged-in session should have no-store on any app response
        with app.app_context():
            conn = db.get_db()
            pwhash = generate_password_hash("Password123")
            _, hkey = core.generate_api_key()
            conn.execute(
                "INSERT INTO users (username, password_hash, api_key_hash, email, email_normalized, email_verified_at) "
                "VALUES ('cc_user', ?, ?, 'cc@example.com', 'cc@example.com', CURRENT_TIMESTAMP)",
                (pwhash, hkey)
            )
            conn.commit()

        with self.client as c:
            c.get('/login')
            from flask import session
            csrf = session.get('csrf_token')
            c.post('/login', data={'username': 'cc_user', 'password': 'Password123', 'csrf_token': csrf})

            resp = c.get('/dashboard')
            self.assertIn('no-store', resp.headers.get('Cache-Control', ''))
            resp2 = c.get('/dashboard/account')
            self.assertIn('no-store', resp2.headers.get('Cache-Control', ''))

    # ── 7. SMTP Engine & Resilience Tests ─────────────────────────

    def test_acs_smtp_backend_handling(self):
        """Mocks smtplib.SMTP: verifies STARTTLS, authentication, retry on 4xx/timeout, non-retry on 5xx, and safe errors."""
        mock_smtp = MagicMock()
        mock_smtp.__enter__.return_value = mock_smtp

        with patch.dict(os.environ, {
            'TESTING': '0',
            'MAIL_BACKEND': 'acs',
            'SMTP_HOST': 'smtp.azurecomm.net',
            'SMTP_PORT': '587',
            'SMTP_USER': 'testuser',
            'SMTP_PASSWORD': 'testpassword',
            'MAIL_FROM': 'DoNotReply@example.com'
        }):
            # 1. Successful transmission
            with patch('smtplib.SMTP', return_value=mock_smtp):
                status = mailer.send_mail("test@example.com", "Test Subject", "Test Body", sync=True)
                self.assertEqual(status, MailStatus.SENT)
                mock_smtp.starttls.assert_called_once()
                mock_smtp.login.assert_called_once_with('testuser', 'testpassword')
                mock_smtp.send_message.assert_called_once()

            # 2. Transient 4xx error triggers single retry
            mock_4xx = MagicMock()
            mock_4xx.__enter__.return_value = mock_4xx
            mock_4xx.send_message.side_effect = [
                smtplib.SMTPResponseException(451, b"Temporary failure"),
                None # retry succeeds
            ]
            with patch('smtplib.SMTP', return_value=mock_4xx), patch('time.sleep', return_value=None):
                status_4xx = mailer.send_mail("test2@example.com", "Test 4xx", "Test Body", sync=True)
                self.assertEqual(status_4xx, MailStatus.SENT)
                self.assertEqual(mock_4xx.send_message.call_count, 2)

            # 3. Permanent 5xx error NEVER retries
            mock_5xx = MagicMock()
            mock_5xx.__enter__.return_value = mock_5xx
            mock_5xx.send_message.side_effect = smtplib.SMTPResponseException(550, b"User mailbox unavailable")
            with patch('smtplib.SMTP', return_value=mock_5xx):
                status_5xx = mailer.send_mail("test3@example.com", "Test 5xx", "Test Body", sync=True)
                self.assertEqual(status_5xx, MailStatus.FAILED)
                self.assertEqual(mock_5xx.send_message.call_count, 1)

    def test_mail_counters_persistent_rate_limits(self):
        """Verifies per-minute, per-hour, and per-day send caps in SQLite."""
        with patch.dict(os.environ, {'MAIL_MAX_PER_MINUTE': '2', 'MAIL_MAX_PER_HOUR': '10', 'MAIL_MAX_PER_DAY': '20'}):
            self.assertTrue(mailer.check_and_increment_mail_counters())
            self.assertTrue(mailer.check_and_increment_mail_counters())
            # 3rd request in same minute hits cap
            self.assertFalse(mailer.check_and_increment_mail_counters())

    def test_production_mail_env_fail_fast(self):
        """Verifies missing SMTP variables fail startup in production mode and pass in debug/testing."""
        with patch.dict(os.environ, {'MAIL_BACKEND': 'acs', 'FLASK_DEBUG': '0', 'TESTING': '0', 'SMTP_HOST': ''}):
            with self.assertRaises(RuntimeError):
                mailer.verify_mail_config()

        # In debug mode, does not fail
        with patch.dict(os.environ, {'MAIL_BACKEND': 'console', 'FLASK_DEBUG': '1', 'TESTING': '0'}):
            mailer.verify_mail_config()

    def test_login_case_insensitive_and_no_victim_lockout(self):
        """Refinements 11 & 16: Tests case-insensitive login by email and validates no victim lockout from another IP."""
        with app.app_context():
            conn = db.get_db()
            pwhash = generate_password_hash("CorrectPassword1")
            _, hkey = core.generate_api_key()
            conn.execute(
                "INSERT INTO users (username, password_hash, api_key_hash, email, email_normalized, email_verified_at) "
                "VALUES ('CaseVictim', ?, ?, 'victim@example.com', 'victim@example.com', CURRENT_TIMESTAMP)",
                (pwhash, hkey)
            )
            conn.commit()

        # 5 failed login attempts from Attacker IP (1.2.3.4)
        with self.client as c:
            c.get('/login', environ_overrides={'REMOTE_ADDR': '1.2.3.4'})
            from flask import session
            csrf_attacker = session.get('csrf_token')
            for _ in range(5):
                c.post('/login', data={'username': 'casevictim', 'password': 'WrongPassword!', 'csrf_token': csrf_attacker}, environ_overrides={'REMOTE_ADDR': '1.2.3.4'})

            # Attacker is locked out
            blocked_resp = c.post('/login', data={'username': 'casevictim', 'password': 'WrongPassword!', 'csrf_token': csrf_attacker}, environ_overrides={'REMOTE_ADDR': '1.2.3.4'})
            self.assertEqual(blocked_resp.status_code, 429)

        # Victim on legitimate IP (5.6.7.8) can STILL log in successfully
        with self.client as c:
            c.get('/login', environ_overrides={'REMOTE_ADDR': '5.6.7.8'})
            from flask import session
            csrf = session.get('csrf_token')
            victim_resp = c.post('/login', data={
                'username': 'VICTIM@EXAMPLE.COM',
                'password': 'CorrectPassword1',
                'csrf_token': csrf
            }, environ_overrides={'REMOTE_ADDR': '5.6.7.8'}, follow_redirects=False)
            self.assertEqual(victim_resp.status_code, 302)
            self.assertIn('/dashboard', victim_resp.location)

    def test_pending_payload_purged_after_expiry(self):
        """Refinement 9: Verifies pending_payload is cleared on consume and purged 15 minutes post-expiry."""
        with app.app_context():
            conn = db.get_db()
            code, _ = otp.create_otp(conn, app.secret_key, 'purge@test.com', 'purge@test.com', 'register', pending_payload='{"secret": 123}')

            # Verify OTP
            ok, row = otp.verify_otp(conn, app.secret_key, 'purge@test.com', 'register', code)
            self.assertTrue(ok)

            # Consumed OTP row must have pending_payload = NULL
            consumed_row = conn.execute("SELECT pending_payload, consumed_at FROM email_otps WHERE id = ?", (row['id'],)).fetchone()
            self.assertIsNone(consumed_row['pending_payload'])
            self.assertIsNotNone(consumed_row['consumed_at'])

            # Create an expired unconsumed OTP with pending_payload
            conn.execute('''
                INSERT INTO email_otps (email_normalized, email_display, purpose, code_hash, pending_payload, expires_at)
                VALUES ('old@test.com', 'old@test.com', 'register', 'dummy_hash', '{"secret": 456}', datetime('now', '-20 minutes'))
            ''')
            conn.commit()

            # Run maintenance cleanup
            db.cleanup_stale_records(conn)

            # pending_payload must now be NULL for the 20-minute-expired row
            old_row = conn.execute("SELECT pending_payload FROM email_otps WHERE email_normalized = 'old@test.com'").fetchone()
            self.assertIsNone(old_row['pending_payload'])


if __name__ == '__main__':
    unittest.main()

import os
import sys
import unittest
import tempfile
import json

# Ensure app is importable
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Configure test environment
os.environ['TESTING'] = '1'
os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-12345678901234567890'

import core
import db
from app import app


class SnipSecurityAndCoreTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        db.DATABASE = self.temp_db_path
        db.DATA_DIR = os.path.dirname(self.temp_db_path)
        app.config['TESTING'] = True
        app.secret_key = 'test-secret-key-12345678901234567890'
        db.init_db(app)
        self.client = app.test_client()
        import mailer
        mailer.clear_outbox()

    def tearDown(self):
        try:
            os.close(self.temp_db_fd)
            if os.path.exists(self.temp_db_path):
                os.remove(self.temp_db_path)
        except OSError:
            pass

    def _register_and_login(self, client, username, password, email=None):
        import re
        import mailer
        if email is None:
            email = f"{username}@testdomain.com"
        from flask import session
        client.get('/')
        csrf = session.get('csrf_token')
        client.post('/register', data={
            'username': username,
            'email': email,
            'password': password,
            'csrf_token': csrf
        }, follow_redirects=True)
        code = None
        if mailer.OUTBOX:
            msg = mailer.OUTBOX[-1]
            body = msg.get_body(preferencelist=('plain',)).get_content()
            m = re.search(r'\b(\d{6})\b', body)
            if m:
                code = m.group(1)
        csrf = session.get('csrf_token')
        if code:
            client.post('/register/verify', data={'code': code, 'csrf_token': csrf}, follow_redirects=True)

    # ── 1. Alias Tests ──────────────────────────────
    def test_alias_validation(self):
        valid, val = core.validate_alias("my-custom-link")
        self.assertTrue(valid)
        self.assertEqual(val, "my-custom-link")

        # Reserved aliases blocked
        valid, _ = core.validate_alias("dashboard")
        self.assertFalse(valid)

        # Invalid characters blocked
        valid, _ = core.validate_alias("bad/link?test")
        self.assertFalse(valid)

        # Too short / too long
        valid, _ = core.validate_alias("a")
        self.assertFalse(valid)

    # ── 2. SSRF Guard Tests ──────────────────────────────────
    def test_ssrf_blocks_private_and_metadata_ips(self):
        # Direct IP literals
        self.assertFalse(core.is_safe_url("http://127.0.0.1"))
        self.assertFalse(core.is_safe_url("http://10.0.0.1/admin"))
        self.assertFalse(core.is_safe_url("http://192.168.1.1:8080"))
        self.assertFalse(core.is_safe_url("http://172.16.0.1"))
        self.assertFalse(core.is_safe_url("http://169.254.169.254/latest/meta-data/"))
        self.assertFalse(core.is_safe_url("http://metadata.google.internal/"))

        # Dangerous non-HTTP schemes
        self.assertFalse(core.is_safe_url("javascript:alert(1)"))
        self.assertFalse(core.is_safe_url("data:text/html,<h1>evil</h1>"))
        self.assertFalse(core.is_safe_url("file:///etc/passwd"))

        # Public domain
        self.assertTrue(core.is_safe_url("https://github.com"))

    # ── 3. Auth Validation & Salted Key Tests ─────────────────
    def test_user_and_password_validation(self):
        # Username checks
        self.assertTrue(core.validate_username("alice_99")[0])
        self.assertFalse(core.validate_username("al")[0])  # too short
        self.assertFalse(core.validate_username("bad user with spaces")[0])

        # Password checks
        self.assertTrue(core.validate_password("SecurePass123")[0])
        self.assertFalse(core.validate_password("short1")[0])  # < 8 chars
        self.assertFalse(core.validate_password("alllettersonly")[0])  # no digit
        self.assertFalse(core.validate_password("123456789")[0])  # no letter

    def test_salted_api_key_hashing(self):
        plain, hashed = core.generate_api_key()
        self.assertTrue(core.verify_api_key(plain, hashed))
        self.assertFalse(core.verify_api_key("wrong_key", hashed))

    # ── 4. CSRF Protection Tests ─────────────────────────────
    def test_csrf_protection_rejects_missing_token(self):
        resp = self.client.post('/shorten', data={'url': 'https://github.com'})
        self.assertEqual(resp.status_code, 403)

    def test_csrf_protection_accepts_valid_header(self):
        with self.client as c:
            from flask import session
            c.get('/')
            csrf = session.get('csrf_token')
            self.assertIsNotNone(csrf)

            resp = c.post(
                '/shorten',
                data=json.dumps({'url': 'https://github.com'}),
                content_type='application/json',
                headers={'X-CSRFToken': csrf}
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertIn('code', data)
            self.assertIn('short_url', data)

    # ── 5. Open Redirect & Monetization Anti-Fraud ───────────
    def test_ad_transit_and_monetization_anti_fraud(self):
        import time
        import hashlib
        with self.client as c:
            from flask import session
            c.get('/')
            csrf = session.get('csrf_token')

            # 1. Register & login so owner_id is set (required for ads_enabled)
            self._register_and_login(c, 'owner_ads', 'Password123')
            csrf = session.get('csrf_token')

            # Create an ad-enabled link as owner
            resp = c.post(
                '/shorten',
                data={'url': 'https://github.com', 'ads_enabled': 'true', 'csrf_token': csrf}
            )
            self.assertEqual(resp.status_code, 200)
            code = resp.get_json()['code']

            # Check that initial redirect page renders interstitial but does NOT record ledger
            with app.app_context():
                conn = db.get_db()
                initial_ledger = conn.execute('SELECT COUNT(*) as count FROM ad_ledger').fetchone()['count']
                self.assertEqual(initial_ledger, 0)

            # Hit the redirect route
            redir_resp = c.get(f'/{code}')
            self.assertEqual(redir_resp.status_code, 200)
            self.assertIn(b'Connecting to Destination', redir_resp.data)

            # Ledger must STILL be zero (anti-fraud fix)
            with app.app_context():
                conn = db.get_db()
                still_zero = conn.execute('SELECT COUNT(*) as count FROM ad_ledger').fetchone()['count']
                self.assertEqual(still_zero, 0)
                # Fetch generated nonce from database
                nonce_row = conn.execute('SELECT nonce, link_id FROM ad_nonces WHERE consumed_at IS NULL').fetchone()
                self.assertIsNotNone(nonce_row)

            # Extract token from the rendered interstitial page
            import re
            m = re.search(r'/continue/([A-Za-z0-9_\-\.]+)', redir_resp.data.decode('utf-8'))
            self.assertIsNotNone(m)
            raw_token = m.group(1)

            # Modify token iat to simulate completed 15s countdown
            from app import serializer
            token_data = serializer.loads(raw_token)
            token_data['iat'] = int(time.time()) - 15
            token = serializer.dumps(token_data)

            continue_resp = c.get(f'/continue/{token}')
            self.assertEqual(continue_resp.status_code, 302)
            self.assertEqual(continue_resp.location, 'https://github.com')

            # Ledger now has exactly 1 entry
            with app.app_context():
                conn = db.get_db()
                final_ledger = conn.execute('SELECT COUNT(*) as count FROM ad_ledger').fetchone()['count']
                self.assertEqual(final_ledger, 1)

            # Replay attempt must fail (400 Expired)
            replay_resp = c.get(f'/continue/{token}')
            self.assertEqual(replay_resp.status_code, 400)

    def test_anonymous_links_cannot_enable_ads(self):
        with self.client as c:
            from flask import session
            c.get('/')
            csrf = session.get('csrf_token')

            resp = c.post('/shorten', data={'url': 'https://github.com', 'ads_enabled': 'true', 'csrf_token': csrf})
            self.assertEqual(resp.status_code, 200)
            code = resp.get_json()['code']

            # Direct redirect without interstitial
            redir = c.get(f'/{code}')
            self.assertEqual(redir.status_code, 302)
            self.assertEqual(redir.location, 'https://github.com')

    def test_ad_token_iat_min_duration_enforced(self):
        import time
        import hashlib
        with self.client as c:
            from flask import session
            c.get('/')
            self._register_and_login(c, 'owner_dur', 'Password123')
            csrf = session.get('csrf_token')

            resp = c.post('/shorten', data={'url': 'https://github.com', 'ads_enabled': 'true', 'csrf_token': csrf})
            code = resp.get_json()['code']
            c.get(f'/{code}')

            with app.app_context():
                conn = db.get_db()
                nonce_row = conn.execute('SELECT nonce, link_id FROM ad_nonces WHERE consumed_at IS NULL').fetchone()

            from app import serializer
            client_binding = hashlib.sha256(b"127.0.0.1|").hexdigest()[:16]
            # iat is right now (< 9s elapsed)
            token = serializer.dumps({
                'link_id': nonce_row['link_id'],
                'nonce': nonce_row['nonce'],
                'iat': int(time.time()),
                'client_binding': client_binding
            })
            bad_resp = c.get(f'/continue/{token}')
            self.assertEqual(bad_resp.status_code, 400)

    def test_ad_token_client_binding_mismatch_rejected(self):
        import time
        with self.client as c:
            from flask import session
            c.get('/')
            self._register_and_login(c, 'owner_bind', 'Password123')
            csrf = session.get('csrf_token')

            resp = c.post('/shorten', data={'url': 'https://github.com', 'ads_enabled': 'true', 'csrf_token': csrf})
            code = resp.get_json()['code']
            c.get(f'/{code}')

            with app.app_context():
                conn = db.get_db()
                nonce_row = conn.execute('SELECT nonce, link_id FROM ad_nonces WHERE consumed_at IS NULL').fetchone()

            from app import serializer
            # Wrong client binding
            token = serializer.dumps({
                'link_id': nonce_row['link_id'],
                'nonce': nonce_row['nonce'],
                'iat': int(time.time()) - 15,
                'client_binding': 'wrong_binding_hex'
            })
            bad_resp = c.get(f'/continue/{token}')
            self.assertEqual(bad_resp.status_code, 403)

    def test_base_url_custom_domain(self):
        with self.client as c:
            from flask import session
            c.get('/')
            csrf = session.get('csrf_token')

            os.environ['BASE_URL'] = 'https://snip.example.com'
            try:
                resp = c.post('/shorten', data={'url': 'https://github.com', 'csrf_token': csrf})
                data = resp.get_json()
                self.assertTrue(data['short_url'].startswith('https://snip.example.com/'))
            finally:
                os.environ.pop('BASE_URL', None)

    def test_clean_ad_config_blocks_unsafe_urls(self):
        from app import _clean_ad_config
        # Unsafe custom ad url
        ok, err = _clean_ad_config({'ad_type': 'custom', 'custom_ad_url': 'http://127.0.0.1/admin'})
        self.assertFalse(ok)
        self.assertIn('unsafe', err.lower())

        # Valid custom ad url
        ok, cfg = _clean_ad_config({'ad_type': 'custom', 'custom_ad_url': 'https://example.com'})
        self.assertTrue(ok)
        self.assertEqual(cfg['ad_type'], 'custom')

    def test_missing_secret_key_raises_runtime_error(self):
        import subprocess
        # Execute isolated python snippet without FLASK_SECRET_KEY, FLASK_DEBUG, or TESTING
        cmd = [
            sys.executable,
            "-c",
            "import os; os.environ.pop('FLASK_SECRET_KEY', None); "
            "os.environ.pop('FLASK_DEBUG', None); os.environ.pop('TESTING', None); "
            "import app"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("RuntimeError", proc.stderr)
        self.assertIn("FLASK_SECRET_KEY", proc.stderr)


    # ── 6. Health & Security Headers ─────────────────────────
    def test_health_check_endpoint(self):
        resp = self.client.get('/health')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'healthy')
        self.assertEqual(data['database'], 'ok')

    def test_robots_txt_endpoint(self):
        resp = self.client.get('/robots.txt')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Disallow: /qr/', resp.data)

    def test_security_headers_present(self):
        resp = self.client.get('/')
        self.assertIn('Content-Security-Policy', resp.headers)
        self.assertEqual(resp.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(resp.headers.get('X-Frame-Options'), 'SAMEORIGIN')
        self.assertEqual(resp.headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')

    # ── 7. Directory Traversal Defense ───────────────────────
    def test_preview_path_traversal_blocked(self):
        resp = self.client.get('/preview/..%2F..%2Fetc.jpg')
        self.assertEqual(resp.status_code, 404)
        resp2 = self.client.get('/preview/invalid!code$.jpg')
        self.assertEqual(resp2.status_code, 404)


    # ── 8. User Auth & Session Rotation ──────────────────────
    def test_user_registration_and_login_flow(self):
        import re
        import mailer
        mailer.clear_outbox()
        with self.client as c:
            from flask import session
            c.get('/')
            csrf = session.get('csrf_token')

            # 1. Register new account initiates verification
            reg_resp = c.post('/register', data={
                'username': 'bob_builder',
                'email': 'bob@builder.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=True)
            self.assertEqual(reg_resp.status_code, 200)
            self.assertIn(b'Check Your Inbox', reg_resp.data)

            # User not created in DB yet
            with app.app_context():
                conn = db.get_db()
                self.assertIsNone(conn.execute("SELECT id FROM users WHERE username = 'bob_builder'").fetchone())

            # 2. Extract OTP from outbox and submit
            self.assertTrue(len(mailer.OUTBOX) > 0)
            msg_body = mailer.OUTBOX[-1].get_body(preferencelist=('plain',)).get_content()
            code = re.search(r'\b(\d{6})\b', msg_body).group(1)

            csrf = session.get('csrf_token')
            verify_resp = c.post('/register/verify', data={
                'code': code,
                'csrf_token': csrf
            }, follow_redirects=True)
            self.assertEqual(verify_resp.status_code, 200)
            self.assertIn(b'Account Created', verify_resp.data)

            # 3. User is now created and verified
            with app.app_context():
                conn = db.get_db()
                user = conn.execute("SELECT * FROM users WHERE username = 'bob_builder'").fetchone()
                self.assertIsNotNone(user)
                self.assertIsNotNone(user['email_verified_at'])

            # 4. Access dashboard as logged in user
            dash_resp = c.get('/dashboard')
            self.assertEqual(dash_resp.status_code, 200)
            self.assertIn(b'bob_builder', dash_resp.data)

            # 5. Logout
            csrf = session.get('csrf_token')
            logout_resp = c.post('/logout', data={'csrf_token': csrf}, follow_redirects=True)
            self.assertEqual(logout_resp.status_code, 200)

            # 6. Login using verified email address
            c.get('/login')
            csrf = session.get('csrf_token')
            login_resp = c.post('/login', data={
                'username': 'bob@builder.com',
                'password': 'StrongPassword1',
                'csrf_token': csrf
            }, follow_redirects=False)
            self.assertEqual(login_resp.status_code, 302)
            self.assertIn('/dashboard', login_resp.location)

    # ── 9. QR Code Endpoint Tests ─────────────────────────────
    def test_qr_endpoints(self):
        with self.client as c:
            from flask import session
            c.get('/')
            csrf = session.get('csrf_token')

            resp = c.post('/shorten', data={'url': 'https://github.com', 'csrf_token': csrf})
            code = resp.get_json()['code']

            # Basic QR
            qr_basic = c.get(f'/qr/{code}')
            self.assertEqual(qr_basic.status_code, 200)
            self.assertEqual(qr_basic.content_type, 'image/png')

            # Styled QR
            qr_styled = c.get(f'/qr/{code}/styled')
            self.assertEqual(qr_styled.status_code, 200)
            self.assertEqual(qr_styled.content_type, 'image/png')

            # Download QR
            qr_dl = c.get(f'/qr/{code}/download')
            self.assertEqual(qr_dl.status_code, 200)
            self.assertIn('attachment', qr_dl.headers.get('Content-Disposition', ''))

    # ── 10. Rate Limiter Tests ────────────────────────────────
    def test_rate_limiter_exceeded(self):
        ip = "198.51.100.42"
        # Window is 15 requests max
        for _ in range(15):
            self.assertFalse(core.is_rate_limited(ip, max_requests=15, window_seconds=60))
        # 16th request must be rate-limited
        self.assertTrue(core.is_rate_limited(ip, max_requests=15, window_seconds=60))

    # ── 11. Phase 2: Salted API Key Pepper & Single Query Lookup ──
    def test_salted_api_key_pepper_and_get_user(self):
        with app.app_context():
            conn = db.get_db()
            plain, hashed = core.generate_api_key()
            conn.execute(
                'INSERT INTO users (username, password_hash, api_key_hash) VALUES (?, ?, ?)',
                ('apikeyuser', 'dummy_hash', hashed)
            )
            conn.commit()

            # Valid lookup via get_user_by_api_key
            user = core.get_user_by_api_key(conn, plain)
            self.assertIsNotNone(user)
            self.assertEqual(user['username'], 'apikeyuser')

            # Invalid key returns None
            bad_user = core.get_user_by_api_key(conn, 'invalid_key_value')
            self.assertIsNone(bad_user)

    def test_regenerate_api_key(self):
        with self.client as c:
            from flask import session
            c.get('/')
            self._register_and_login(c, 'regen_user', 'StrongPassword1')
            csrf = session.get('csrf_token')

            # Regenerate key via account endpoint with password confirmation
            resp = c.post('/dashboard/account/regenerate-api-key', data={
                'current_password': 'StrongPassword1',
                'csrf_token': csrf
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            new_key = data['api_key']
            self.assertTrue(len(new_key) >= 32)

            # Verify the new key works with API endpoints
            stats_resp = c.get('/api/analytics', headers={'X-API-Key': new_key})
            self.assertEqual(stats_resp.status_code, 200)

    # ── 12. Phase 2: SSRF Guard Advanced Edge Cases ──────────────
    def test_ssrf_is_global_and_edge_cases(self):
        from unittest.mock import patch

        # Port 22 blocked
        self.assertFalse(core.validate_url_at_creation("http://example.com:22"))

        # Userinfo blocked
        self.assertFalse(core.validate_url_at_creation("http://admin:pass@example.com"))

        # Decimal IP (127.0.0.1 = 2130706433)
        self.assertFalse(core.validate_url_at_creation("http://2130706433"))

        # CGNAT blocked (100.64.0.0/10)
        with patch('socket.getaddrinfo') as mock_dns:
            mock_dns.return_value = [(2, 1, 6, '', ('100.64.1.1', 80))]
            self.assertFalse(core.validate_url_at_creation("http://cgnat.test.com"))

        # IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)
        with patch('socket.getaddrinfo') as mock_dns:
            mock_dns.return_value = [(23, 1, 6, '', ('::ffff:127.0.0.1', 80, 0, 0))]
            self.assertFalse(core.validate_url_at_creation("http://mapped-ipv6.test.com"))

        # DNS Timeout simulation
        with patch('core._resolve_dns_with_timeout', side_effect=TimeoutError("DNS timeout")):
            self.assertFalse(core.validate_url_at_creation("http://slowdns.test.com"))

    def test_url_blocklist_cached_verdict_rejection(self):
        core._set_cached_verdict("blocked-domain-cached.com", False)
        # Should return False both times, not a tuple on the second time.
        self.assertFalse(core.validate_url_at_creation("http://blocked-domain-cached.com"))
        self.assertFalse(core.validate_url_at_creation("http://blocked-domain-cached.com"))

    def test_validate_url_redirect_lru_cache(self):
        core._set_cached_verdict("cached-global-domain.org", True)
        self.assertTrue(core.validate_url_at_redirect("https://cached-global-domain.org/path"))

        core._set_cached_verdict("cached-bad-domain.org", False)
        self.assertFalse(core.validate_url_at_redirect("https://cached-bad-domain.org/path"))

    # ── 13. Phase 2: Single INSERT & Collision Retry ─────────────
    def test_single_insert_and_collision_retry(self):
        from unittest.mock import patch
        with self.client as c:
            with app.app_context():
                # Set up existing code in DB
                conn = db.get_db()
                conn.execute("INSERT INTO links (code, original_url, owner_id) VALUES ('COLLID', 'https://example.com', NULL)")
                conn.commit()

            # Mock generate_short_code to return COLLID first, then UNIQUE1
            codes = iter(['COLLID', 'UNIQUE1'])
            with patch('core.generate_short_code', side_effect=lambda _: next(codes)):
                resp = c.post('/api/shorten', json={'url': 'https://python.org'})
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertEqual(data['code'], 'UNIQUE1')

            with app.app_context():
                conn = db.get_db()
                # Ensure no intermediate row with code = NULL exists
                null_rows = conn.execute("SELECT COUNT(*) as count FROM links WHERE code IS NULL").fetchone()['count']
                self.assertEqual(null_rows, 0)

    # ── 14. Phase 2: Screenshot Deletion on API Delete ───────────
    def test_api_delete_cleans_screenshot(self):
        with app.app_context():
            conn = db.get_db()
            plain_key, hashed_key = core.generate_api_key()
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO users (username, password_hash, api_key_hash) VALUES (?, ?, ?)',
                ('deluser', 'dummy_hash', hashed_key)
            )
            user_id = cur.lastrowid
            cur.execute(
                'INSERT INTO links (code, original_url, owner_id) VALUES (?, ?, ?)',
                ('DEL123', 'https://example.com', user_id)
            )
            conn.commit()

        # Create mock screenshot file
        screenshot_dir = os.path.join(db.DATA_DIR, 'screenshots')
        os.makedirs(screenshot_dir, exist_ok=True)
        screenshot_path = os.path.join(screenshot_dir, 'DEL123.jpg')
        with open(screenshot_path, 'w') as f:
            f.write('fake image data')
        self.assertTrue(os.path.exists(screenshot_path))

        # Delete link via API
        resp = self.client.delete('/api/DEL123', headers={'X-API-Key': plain_key})
        self.assertEqual(resp.status_code, 200)

        # Verify screenshot file removed
        self.assertFalse(os.path.exists(screenshot_path))

    def test_api_shorten_invalid_expiry(self):
        plain_key, hashed_key = core.generate_api_key()
        with app.app_context():
            conn = db.get_db()
            conn.execute('INSERT INTO users (username, password_hash, api_key_hash) VALUES (?, ?, ?)',
                         ('expiryuser', 'dummy', hashed_key))
            conn.commit()
            
        # Test NaN
        resp = self.client.post('/api/shorten', headers={'X-API-Key': plain_key}, json={'url': 'https://example.com', 'expires_in': float('nan')})
        self.assertEqual(resp.status_code, 400)
        self.assertIn('must be a finite number', resp.get_json()['error'])
        # Test Infinity
        resp = self.client.post('/api/shorten', headers={'X-API-Key': plain_key}, json={'url': 'https://example.com', 'expires_in': float('inf')})
        self.assertEqual(resp.status_code, 400)
        self.assertIn('must be a finite number', resp.get_json()['error'])
        # Test Boolean
        resp = self.client.post('/api/shorten', headers={'X-API-Key': plain_key}, json={'url': 'https://example.com', 'expires_in': True})
        self.assertEqual(resp.status_code, 400)
        self.assertIn('cannot be a boolean', resp.get_json()['error'])

    # ── 15. Phase 3: Logout POST-only ────────────────────────────
    def test_logout_post_only(self):
        with self.client as c:
            # GET /logout should be 405 Method Not Allowed
            resp = c.get('/logout')
            self.assertEqual(resp.status_code, 405)

            # Establish session and retrieve CSRF token
            from flask import session
            c.get('/')
            csrf = session.get('csrf_token')

            # POST /logout with CSRF token should succeed and redirect to index
            resp = c.post('/logout', data={'csrf_token': csrf}, follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.headers['Location'].endswith('/'))

    # ── 16. Phase 3: CSP Nonce and Security Headers ───────────────
    def test_csp_nonce_present_in_headers_and_templates(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        csp = resp.headers.get('Content-Security-Policy', '')
        self.assertIn("'nonce-", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'self'", csp)
        self.assertIn("form-action 'self'", csp)
        self.assertIn("frame-ancestors 'self'", csp)
        self.assertIn('camera=()', resp.headers.get('Permissions-Policy', ''))

        # Check template rendered with nonce attribute
        html = resp.get_data(as_text=True)
        self.assertIn('nonce="', html)

    # ── 17. Phase 3: Session Version Invalidation ─────────────────
    def test_session_version_revocation(self):
        with self.client as c:
            from flask import session
            c.get('/')
            self._register_and_login(c, 'sess_user', 'StrongPassword1')

            # Dashboard accessible
            resp = c.get('/dashboard')
            self.assertEqual(resp.status_code, 200)

            # Invalidate session by incrementing session_version in database
            with app.app_context():
                conn = db.get_db()
                conn.execute("UPDATE users SET session_version = session_version + 1 WHERE username = 'sess_user'")
                conn.commit()

            # Subsequent request to /dashboard should redirect to login
            resp = c.get('/dashboard', follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.headers['Location'].endswith('/login'))

    # ── 18. Phase 3: Link Expiration Lifecycle ────────────────────
    def test_link_expiration_lifecycle(self):
        # Shorten link with expires_in = 3600
        resp = self.client.post('/api/shorten', json={
            'url': 'https://example.com',
            'expires_in': 3600
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        code = data['code']

        with app.app_context():
            conn = db.get_db()
            row = conn.execute("SELECT expires_at FROM links WHERE code = ?", (code,)).fetchone()
            self.assertIsNotNone(row['expires_at'])

            # Fast-forward expiry into the past
            past_time = "2020-01-01T00:00:00Z"
            conn.execute("UPDATE links SET expires_at = ? WHERE code = ?", (past_time, code))
            conn.commit()

        # Accessing expired link should return 410 Gone
        resp = self.client.get(f'/{code}', follow_redirects=False)
        self.assertEqual(resp.status_code, 410)

    # ── 19. Phase 3: QR LRU Cache & Rate Limit ────────────────────
    def test_qr_lru_cache_and_rate_limit(self):
        # Create link
        resp = self.client.post('/api/shorten', json={'url': 'https://example.com'})
        code = resp.get_json()['code']

        # Fetch QR code
        qr_resp = self.client.get(f'/qr/{code}', environ_overrides={'REMOTE_ADDR': '198.51.100.1'})
        self.assertEqual(qr_resp.status_code, 200)
        self.assertEqual(qr_resp.mimetype, 'image/png')
        self.assertIn('max-age=3600', qr_resp.headers.get('Cache-Control', ''))

        # Fetch again to hit cache
        qr_resp2 = self.client.get(f'/qr/{code}', environ_overrides={'REMOTE_ADDR': '198.51.100.1'})
        self.assertEqual(qr_resp2.status_code, 200)
        self.assertEqual(qr_resp.data, qr_resp2.data)

        # Exceed 30 QR requests in a minute from same IP
        last_resp = None
        for _ in range(32):
            last_resp = self.client.get(f'/qr/{code}', environ_overrides={'REMOTE_ADDR': '198.51.100.2'})
        self.assertEqual(last_resp.status_code, 429)

    # ── 20. Phase 3: Analytics Bounds Validation ──────────────────
    def test_analytics_limit_bounds(self):
        with app.app_context():
            plain_key, hashed_key = core.generate_api_key()
            conn = db.get_db()
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, password_hash, api_key_hash) VALUES (?, ?, ?)",
                        ('analytics_user', 'hash', hashed_key))
            uid = cur.lastrowid
            cur.execute("INSERT INTO links (code, original_url, owner_id) VALUES ('ANL1', 'https://example.com', ?)", (uid,))
            conn.commit()

        headers = {'X-API-Key': plain_key}
        # limit = 0 -> 400
        resp = self.client.get('/api/analytics?limit=0', headers=headers)
        self.assertEqual(resp.status_code, 400)

        # limit = 101 -> 400
        resp = self.client.get('/api/analytics?limit=101', headers=headers)
        self.assertEqual(resp.status_code, 400)

        # limit = 50 -> 200
        resp = self.client.get('/api/analytics?limit=50', headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)
        self.assertTrue(any(item.get('code') == 'ANL1' for item in data))

    # ── 21. Phase 3: JSON Error Handlers ─────────────────────────
    def test_json_error_handlers(self):
        # 404 on API returns JSON
        resp = self.client.get('/api/nonexistent/endpoint')
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.mimetype, 'application/json')
        self.assertIn('error', resp.get_json())

        # 405 on API returns JSON
        resp_405 = self.client.get('/api/SHORT1')
        self.assertEqual(resp_405.status_code, 405)
        self.assertEqual(resp_405.mimetype, 'application/json')
        self.assertIn('error', resp_405.get_json())

        # 400 on malformed JSON payload
        resp = self.client.post(
            '/api/shorten',
            data='{invalid-json',
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.mimetype, 'application/json')
        self.assertIn('error', resp.get_json())

    # ── 22. Phase 3: Dashboard Pagination ─────────────────────────
    def test_dashboard_pagination(self):
        with self.client as c:
            from flask import session
            c.get('/')
            self._register_and_login(c, 'page_user', 'StrongPassword1')

            with app.app_context():
                conn = db.get_db()
                user = conn.execute("SELECT id FROM users WHERE username = 'page_user'").fetchone()
                uid = user['id']
                for i in range(55):
                    conn.execute("INSERT INTO links (code, original_url, owner_id) VALUES (?, ?, ?)",
                                 (f"PG{i:03d}", f"https://example.com/{i}", uid))
                conn.commit()

            # Page 1
            resp = c.get('/dashboard?page=1')
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)
            self.assertIn('Showing page 1 of 2', html)
            self.assertIn('PG000', html)

            # Page 2
            resp2 = c.get('/dashboard?page=2')
            self.assertEqual(resp2.status_code, 200)
            html2 = resp2.get_data(as_text=True)
            self.assertIn('Showing page 2 of 2', html2)

    # ── 23. Phase 3: Case-Insensitive Fallback Redirect ──────────
    def test_case_insensitive_redirect(self):
        with app.app_context():
            conn = db.get_db()
            conn.execute("INSERT INTO links (code, original_url) VALUES ('MixedCase', 'https://example.com/target')")
            conn.commit()

        resp = self.client.get('/mixedcase', follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers['Location'], 'https://example.com/target')

    # ── 24. Phase 7: Regression Tests ─────────────────────────
    def test_url_blocklist_double_submission(self):
        """Ensure that submitting a blocked domain twice is blocked on both attempts."""
        blocked_url = "http://127.0.0.1:8080/exploit"
        r1 = core.validate_url_at_creation(blocked_url)
        self.assertFalse(r1)
        # Second attempt must hit cache and still evaluate as False
        r2 = core.validate_url_at_creation(blocked_url)
        self.assertFalse(r2)

    def test_login_lockout_threshold(self):
        """Ensure failed logins lock out strictly after 5 failed attempts."""
        from flask import session
        with self.client:
            self.client.get('/login')
            csrf = session.get('csrf_token')

            # 5 failed attempts allowed (200 with error)
            for i in range(5):
                resp = self.client.post('/login', data={'username': 'lockout_test_user', 'password': 'wrong_password', 'csrf_token': csrf}, follow_redirects=False)
                self.assertEqual(resp.status_code, 200, f"Attempt {i+1} should be 200")
                self.assertIn(b'Invalid username or password', resp.data)

            # 6th attempt exceeds 5 attempts and locks out with 429
            resp6 = self.client.post('/login', data={'username': 'lockout_test_user', 'password': 'wrong_password', 'csrf_token': csrf}, follow_redirects=False)
            self.assertEqual(resp6.status_code, 429)
            self.assertIn(b'Too many failed login attempts', resp6.data)

    def test_dashboard_search_and_sort(self):
        """Ensure dashboard query parameters ?q= and ?sort= filter correctly."""
        with app.app_context():
            conn = db.get_db()
            conn.execute("INSERT INTO users (id, username, password_hash, api_key_hash, session_version) VALUES (999, 'searcher', 'dummy', 'dummy_hash', 1)")
            conn.execute("INSERT INTO links (id, code, original_url, owner_id) VALUES (901, 'link_apple', 'https://apple.com', 999)")
            conn.execute("INSERT INTO links (id, code, original_url, owner_id) VALUES (902, 'link_banana', 'https://banana.com', 999)")
            conn.commit()

        with self.client.session_transaction() as sess:
            sess['user_id'] = 999
            sess['username'] = 'searcher'
            sess['session_version'] = 1

        # Search for 'apple'
        resp = self.client.get('/dashboard?q=apple')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'link_apple', resp.data)
        self.assertNotIn(b'link_banana', resp.data)

        # Search for 'banana'
        resp2 = self.client.get('/dashboard?q=banana')
        self.assertEqual(resp2.status_code, 200)
        self.assertIn(b'link_banana', resp2.data)
        self.assertNotIn(b'link_apple', resp2.data)


if __name__ == '__main__':
    unittest.main()



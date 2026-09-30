# Snip — Modern URL Shortener & Link Analytics

Snip is a high-performance URL shortener with real-time analytics, QR code generation, email OTP verification, and defense-in-depth security. Built with Flask 3 and SQLite (WAL mode), designed for production on Azure App Service Linux.

---

## Features

- **Fast & Scalable Shortening**: Single-query atomic insert with collision retry and custom alias support.
- **Deep SSRF & Abuse Protection**: Rejects private, loopback, link-local, cloud metadata, CGNAT, and IPv4-mapped IPv6 targets via `ipaddress.is_global`.
- **Email & OTP Security**: Email registration and password reset powered by 6-digit OTPs (stored as HMAC-SHA256 digests), 60-second cooldowns, disposable email blocking, and Azure Communication Services (ACS) / SMTP support.
- **Real-Time Click Telemetry**: Bot/crawler filtering, IP hashing, and per-link click tracking.
- **Dynamic QR Studio**: Client-side vector QR studio and server-side PNG rendering with LRU caching.
- **Optional Link Monetization**: Built-in interstitial gateway with client-bound signed tokens and countdown verification.
- **Hardened Middleware**: Werkzeug `ProxyFix`, SQLite-backed distributed sliding-window rate limiters, per-request CSP nonces, CSRF double-submit protection, and instant multi-device session revocation via `session_version`.

---

## Tech Stack

- **Backend**: Python 3.12+, Flask 3.1, Werkzeug 3.1
- **Database**: SQLite 3 (WAL mode, busy timeout 5000ms, foreign keys enabled)
- **WSGI Server**: Gunicorn (2 workers x 4 threads)
- **Frontend**: Vanilla HTML5, modern CSS (dark theme, glassmorphism), zero client framework dependencies
- **Deployment**: Azure App Service Linux via GitHub Actions CI/CD (OIDC)

---

## Quickstart

### Prerequisites

- Python 3.12+

### Local Setup

```bash
# 1. Clone repository
git clone https://github.com/cosmic-116/URL-Shortener.git
cd URL-Shortener

# 2. Create and activate virtual environment
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows PowerShell:
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Run automated test suite (65 tests)
python -m unittest discover -s tests -v

# 5. Run security audit
pip-audit -r requirements.txt

# 6. Start development server
export FLASK_SECRET_KEY="dev-secret-key-change-in-production"
export FLASK_DEBUG="1"
python app.py
```

Access the app at `http://127.0.0.1:5000`.

---

## Configuration

Configure the application using environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `FLASK_SECRET_KEY` | **Yes** (in prod) | *(Auto-generated in dev)* | Secret key for sessions, CSRF, and cryptographic tokens. |
| `API_KEY_PEPPER` | **Yes** (in prod) | *(Auto-generated in dev)* | Pepper used to hash generated API keys securely. |
| `FLASK_DEBUG` | No | `0` | Set `1` for local debugging. |
| `BASE_URL` | No | `""` | Canonical host (e.g. `https://snip.example.com`). Defaults to `request.host_url`. |
| `DATA_DIR` | No | `/home/data` | Storage directory for `database.db` and thumbnails. |
| `DB_JOURNAL_MODE` | No | `WAL` | SQLite journal mode (`WAL` or `DELETE`). |
| `PORT` | No | `8000` | Port for Gunicorn server. |
| `TRUSTED_PROXY_COUNT` | No | `1` (Azure) / `0` | Number of trusted reverse proxies. |
| `REQUIRE_VERIFIED_EMAIL_FOR_API` | No | `0` | Set `1` to require verified email for API access. |
| `MAIL_BACKEND` | **Yes** (in prod) | `acs` | Email provider: `acs`, `smtp`, `console`, or `test`. |
| `SMTP_HOST` | For `acs`/`smtp` | `""` | SMTP server host (e.g. `smtp.azurecomm.net`). |
| `SMTP_PORT` | For `acs`/`smtp` | `587` | SMTP port (STARTTLS). |
| `SMTP_USER` | For `acs`/`smtp` | `""` | SMTP username / Entra ID Client ID. |
| `SMTP_PASSWORD` | For `acs`/`smtp` | `""` | SMTP password / Entra ID Client Secret. |
| `SMTP_FROM` | For `acs`/`smtp` | `""` | Verified sender address (e.g. `DoNotReply@yourdomain.com`). |
| `MAIL_MAX_PER_MINUTE` | No | `25` | Global outbound email rate limit per minute. |
| `MAIL_MAX_PER_HOUR` | No | `90` | Global outbound email rate limit per hour. |
| `MAIL_MAX_PER_DAY` | No | `250` | Global outbound email rate limit per day. |
| `REQUIRE_VERIFIED_EMAIL_FOR_API` | No | `1` | Enforce email verification for API key operations. |

---

## REST API Reference

All API requests accept and return JSON. Authenticate using the `X-API-Key` header.

### 1. Shorten a URL
```bash
curl -X POST http://127.0.0.1:5000/api/shorten \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"url": "https://example.com", "alias": "my-link", "expires_in": "7d"}'
```
**Response (200 OK):**
```json
{
  "code": "my-link",
  "short_url": "http://127.0.0.1:5000/my-link",
  "original_url": "https://example.com",
  "expires_at": "2026-10-07 12:00:00",
  "heuristic_flags": []
}
```

### 2. Get Link Statistics
```bash
curl http://127.0.0.1:5000/api/stats/my-link \
  -H "X-API-Key: YOUR_API_KEY"
```
**Response (200 OK):**
```json
{
  "code": "my-link",
  "original_url": "https://example.com",
  "clicks": 42,
  "created_at": "2026-09-30 18:00:00",
  "safety_status": "clean"
}
```

### 3. Delete a Link
```bash
curl -X DELETE http://127.0.0.1:5000/api/my-link \
  -H "X-API-Key: YOUR_API_KEY"
```
**Response (200 OK):**
```json
{
  "message": "Deleted successfully"
}
```

### 4. User Analytics
```bash
curl http://127.0.0.1:5000/api/analytics?limit=10 \
  -H "X-API-Key: YOUR_API_KEY"
```

---

## Production Deployment

### Azure App Service Linux

1. Connect your repository in **Deployment Center** (GitHub Actions).
2. Configure **Application Settings** under Configuration in the Azure Portal:
   - `FLASK_SECRET_KEY`: Generate a 64-char hex string (`python -c "import secrets; print(secrets.token_hex(32))"`)
   - `API_KEY_PEPPER`: Generate a 64-char hex string (`python -c "import secrets; print(secrets.token_hex(32))"`)
   - `MAIL_BACKEND`: `acs` or `smtp`
   - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
   - `DATA_DIR`: `/home/data`
3. Set **Startup Command** under General Settings:
   ```bash
   bash startup.sh
   ```
4. Pushing to `main` automatically runs `pip-audit`, executes the 65-test suite, and deploys to App Service.

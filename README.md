# Advanced Flask URL Shortener

A robust, multi-user URL shortener built with Flask and SQLite. Designed with security, atomicity, and edge cases in mind.

## Implemented Features
1. **Base62 Encoding:** Guaranteed collision-free short codes via Auto-Increment SQLite IDs translated into Base62. Validates inputs and handles `0` mathematically.
2. **Custom Aliases:** Custom aliases are thoroughly validated against a regex allowlist (`[A-Za-z0-9_-]+`), normalized to lowercase, checked for reasonable length constraints, and screened against system reserved words.
3. **Ad Monetization with Fraud Prevention:** Users can opt-in to ads. Tokens are securely generated using `itsdangerous` without leaking the destination URL in the payload. Token replay attacks are mitigated through an atomic `ad_nonces` table that tracks consumed tokens.
4. **Malicious Link Checker (Heuristic & Async):** Uses a basic synchronous heuristic to check for phishing keywords and raw IP literals. Spawns a background thread to queue simulated external safety checking without blocking the user response.
5. **Thread-safe Rate Limiting:** Custom, in-memory sliding window rate limiter utilizing `collections.deque` and `threading.Lock` to prevent TOCTOU race conditions.
6. **Robust Data Persistence:** SQLite schema with `PRAGMA foreign_keys = ON`, utilizing `ON DELETE CASCADE` to prevent orphaned analytics or ledger records. 
7. **Secure Authentication:** 
   - Passwords stored as Werkzeug hashes.
   - API keys are generated securely, displayed exactly once in plaintext, and verified using `SHA-256` hashing and `hmac.compare_digest` in O(1) time.
   - IP addresses are anonymized in the DB using an HMAC-SHA256 signature rather than plaintext or basic SHA-256.

## Known Limitations & Missing Features (Future Work)
- **External Safety API:** The background worker for malicious scanning currently simulates an external HTTP call via a timeout and mock logic. Real integration (e.g., Google Safe Browsing) is not yet implemented.
- **Advanced SSRF Protection (DNS Rebinding):** The `is_safe_url` validation safely screens out obvious IP literal loopbacks/reserved ranges, but it cannot prevent a sophisticated DNS rebinding attack (where a safe hostname resolves to a local IP upon fetch).
- **Process Scope of Rate Limiter:** The rate limiter is local and in-memory. It resets upon application restart and will not coordinate counts if you scale to multiple worker processes (e.g., with Gunicorn).

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables
```bash
export FLASK_SECRET_KEY="your-strong-random-secret"
export FLASK_ENV="development"
```
*(On Windows Powershell, use `$env:FLASK_SECRET_KEY="your-strong-random-secret"`)*

### 3. Run the App
```bash
python app.py
```
*The SQLite database will be automatically created on the first run.*

## API Documentation

All API endpoints that require authentication must include the `X-API-Key` header. If the key is missing or invalid, the API correctly returns `401 Unauthorized`.

### Shorten a Link (Public or Authenticated)
**POST** `/api/shorten`
```json
{
  "url": "https://example.com",
  "alias": "my-custom-name",
  "ads_enabled": true
}
```

### Get Link Stats (Owner Only)
**GET** `/api/stats/<code>`
Returns JSON with click count, creation data, and safety status.

### Delete a Link (Owner Only)
**DELETE** `/api/<code>`

### Analytics (Top Links)
**GET** `/api/analytics?limit=5`
Returns your top N links by click count.

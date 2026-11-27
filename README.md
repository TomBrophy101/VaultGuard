# VaultGuard — Secure Credential & Secret Manager

**Module:** Secure Application Programming (`BSHC4CSFD`)  
**Student:** Tom Brophy (`x23405724`)  
**Tech Stack:** Python 3.14, Flask 3.1, SQLite3, Argon2id (`argon2-cffi`), PBKDF2-HMAC-SHA256 & AES-256-GCM (`cryptography`), Flask-WTF

## 1. Project Overview & SDLC
VaultGuard is a Flask and SQLite3 credential and secret vault developed using a **Build -> Exploit -> Harden -> Verify** workflow across `insecure`, `secure`, and `main` branches, tracked with GitHub Issues and a Kanban board.

## 2. Repository Branches
- `main`: Production-hardened branch merged from `secure`.
- `secure`: Hardened implementation with Argon2id, AES-256-GCM, CSRF protection, password policy, login rate limiting, security headers, and `app.log`.
- `insecure`: Intentionally vulnerable baseline preserved to demonstrate baseline exploits.

## 3. OWASP Top 10 Mitigations
- **SQL Injection (A03):** Parameterized `?` SQLite3 queries and escaped `LIKE` wildcards (`ESCAPE '\\'`).
- **Stored, Reflected & DOM XSS (A03):** Contextual Jinja2 auto-escaping, strict `Content-Security-Policy`, and safe `.textContent` handling in `static/dom_status.js`.
- **Sensitive Data Exposure (A02):** Argon2id password hashing, PBKDF2-HMAC-SHA256 key derivation, and AES-256-GCM encryption with 96-bit nonces.
- **CSRF & Auth/Config Hardening (A01, A05, A07):** `Flask-WTF` CSRF protection, `HttpOnly` and `SameSite=Lax` cookies, `debug=False`, security headers, 12+ character password policy, and 5-attempt login rate limiting.
- **Logging & Monitoring (A09):** Rotating `app.log` audit logging (`RotatingFileHandler`) with newline sanitization against log injection.

## 4. Cryptographic Architecture
- **Passwords:** Hashed with **Argon2id** (`m=65536, t=3, p=4`) and unique salts.
- **Key Derivation:** 256-bit vault key derived via **PBKDF2-HMAC-SHA256** (`600,000` iterations) with a per-user `kdf_salt`.
- **Encryption at Rest:** Vault entries encrypted with **AES-256-GCM** using a unique 12-byte (`96-bit`) random nonce per secret.

## 5. Setup & Verification
```bash
git clone [https://github.com/TomBrophy101/VaultGuard.git](https://github.com/TomBrophy101/VaultGuard.git)
cd VaultGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Verify security headers:
```bash
curl -i -s [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login) | head -n 20
```

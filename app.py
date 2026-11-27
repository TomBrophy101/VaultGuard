import os
import re
import base64
import secrets
import sqlite3
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=1800,
)

csrf = CSRFProtect(app)
ph = PasswordHasher()
DB_NAME = "vaultguard.db"
FAILED_LOGINS = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            kdf_salt BLOB NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()


def derive_vault_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_secret(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ct


def decrypt_secret(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def validate_password_policy(password: str) -> str | None:
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?":{}|<>_\-]", password):
        return "Password must include at least one special character."
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session or "vault_key" not in session:
            session.clear()
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.errorhandler(400)
def bad_request(_e):
    return render_template("login.html", error="Invalid or expired security token."), 400


@app.errorhandler(404)
def not_found(_e):
    return "Page not found.", 404


@app.errorhandler(500)
def internal_error(_e):
    return "An unexpected error occurred.", 500


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
            error = "Username must be 3-32 alphanumeric or underscore characters."
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 120:
            error = "Please enter a valid email address."
        else:
            policy_err = validate_password_policy(password)
            if policy_err:
                error = policy_err

        if not error:
            pw_hash = ph.hash(password)
            kdf_salt = os.urandom(16)
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, email, kdf_salt) VALUES (?, ?, ?, ?)",
                    (username, pw_hash, email, kdf_salt),
                )
                conn.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Registration could not be completed with those details."
            finally:
                conn.close()

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    client_ip = request.remote_addr or "local"

    if request.method == "POST":
        now = time.time()
        attempts, lock_until = FAILED_LOGINS.get(client_ip, (0, 0))
        if now < lock_until:
            error = "Too many failed attempts. Please wait 5 minutes before retrying."
            return render_template("login.html", error=error), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT id, username, password_hash, kdf_salt FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        valid = False
        if user:
            try:
                valid = ph.verify(user["password_hash"], password)
            except VerifyMismatchError:
                valid = False

        if valid:
            FAILED_LOGINS.pop(client_ip, None)
            vault_key = derive_vault_key(password, user["kdf_salt"])
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["vault_key"] = base64.b64encode(vault_key).decode("ascii")
            return redirect(url_for("dashboard"))

        attempts += 1
        if attempts >= MAX_ATTEMPTS:
            FAILED_LOGINS[client_ip] = (attempts, now + LOCKOUT_SECONDS)
        else:
            FAILED_LOGINS[client_ip] = (attempts, 0)
        error = "Invalid username or master password."

    return render_template("login.html", error=error)


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    vault_key = base64.b64decode(session["vault_key"])
    conn = get_db()
    error = None

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        secret_data = request.form.get("secret_data", "")
        if not title or len(title) > 100 or not secret_data or len(secret_data) > 2048:
            error = "Title (1-100 chars) and Secret Data (1-2048 chars) are required."
        else:
            nonce, ct = encrypt_secret(secret_data, vault_key)
            conn.execute(
                "INSERT INTO vault_items (user_id, title, nonce, ciphertext) VALUES (?, ?, ?, ?)",
                (session["user_id"], title, nonce, ct),
            )
            conn.commit()
            conn.close()
            return redirect(url_for("dashboard"))

    q = request.args.get("q", "").strip()
    if q:
        escaped_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = conn.execute(
            "SELECT id, title, nonce, ciphertext FROM vault_items WHERE user_id = ? AND title LIKE ? ESCAPE '\\'",
            (session["user_id"], f"%{escaped_q}%"),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, title, nonce, ciphertext FROM vault_items WHERE user_id = ?",
            (session["user_id"],),
        ).fetchall()
    conn.close()

    decrypted_items = []
    for r in rows:
        try:
            secret_plain = decrypt_secret(r["nonce"], r["ciphertext"], vault_key)
        except Exception:
            secret_plain = "[Decryption Error]"
        decrypted_items.append((r["id"], r["title"], secret_plain))

    return render_template(
        "dashboard.html",
        username=session["username"],
        items=decrypted_items,
        search_query=q,
        error=error,
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)

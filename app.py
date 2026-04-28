from flask import Flask, request, redirect, url_for, session, flash, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import bcrypt
import pyotp
import qrcode
import sqlite3
import base64
from io import BytesIO
import time

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])

DB = "auth.db"
FAILED_LIMIT = 5
LOCK_MINUTES = 15

BASE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 16px; background: #f7f7f7; }
    .card { background: white; padding: 22px; border-radius: 14px; box-shadow: 0 2px 10px rgba(0,0,0,.08); }
    input { width: 100%; padding: 10px; margin: 6px 0 14px; box-sizing: border-box; }
    button { padding: 10px 14px; border: 0; border-radius: 10px; cursor: pointer; }
    .msg { background: #eef7ff; border: 1px solid #b9dbff; padding: 10px; margin: 10px 0; border-radius: 10px; }
    a { text-decoration: none; }
    code, pre { white-space: pre-wrap; word-break: break-word; }
    img { max-width: 260px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>{{ title }}</h1>
    {% for m in get_flashed_messages() %}
      <div class="msg">{{ m }}</div>
    {% endfor %}
    {{ body|safe }}
  </div>
</body>
</html>
"""

def page(title, body):
    return render_template_string(BASE, title=title, body=body)

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lockout_until INTEGER NOT NULL DEFAULT 0,
                last_totp_counter INTEGER NOT NULL DEFAULT -1
            )
        """)

def current_counter():
    return int(time.time()) // 30

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return page("Secure Login Lab", """
        <p>Use this lab app to demonstrate bcrypt password storage, rate limiting, account lockout, and TOTP 2FA.</p>
        <p><a href="/register">Register</a> | <a href="/login">Login</a></p>
    """)

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        secret = pyotp.random_base32()

        try:
            with get_db() as conn:
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
                    (username, password_hash, secret),
                )
                user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))

        session.clear()
        session["pending_2fa_user_id"] = user_id
        flash("Account created. Now scan the QR code and verify 2FA.")
        return redirect(url_for("setup_2fa"))

    return page("Register", """
        <form method="post">
          <label>Username</label>
          <input name="username" required>
          <label>Password</label>
          <input name="password" type="password" required>
          <button type="submit">Create account</button>
        </form>
        <p><a href="/login">Already have an account?</a></p>
    """)

@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    uid = session.get("pending_2fa_user_id")
    if not uid:
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    if not user:
        session.clear()
        flash("Session expired.")
        return redirect(url_for("register"))

    totp = pyotp.TOTP(user["totp_secret"])
    provisioning_uri = totp.provisioning_uri(name=user["username"], issuer_name="Secure Login Lab")
    img = qrcode.make(provisioning_uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if totp.verify(otp, valid_window=1):
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET totp_enabled=1, last_totp_counter=? WHERE id=?",
                    (current_counter(), uid),
                )
            session.pop("pending_2fa_user_id", None)
            session["user_id"] = uid
            flash("2FA enabled and login completed.")
            return redirect(url_for("dashboard"))

        flash("Wrong OTP. Scan the QR code again and try a fresh code.")
        return redirect(url_for("setup_2fa"))

    return page("Enable 2FA", f"""
        <p>Scan this QR code in Google Authenticator or any TOTP app.</p>
        <img src="data:image/png;base64,{qr_b64}" alt="QR code">
        <p><strong>Secret:</strong> <code>{user["totp_secret"]}</code></p>
        <form method="post">
          <label>Enter current OTP</label>
          <input name="otp" inputmode="numeric" required>
          <button type="submit">Verify and enable</button>
        </form>
    """)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if not user:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        now = int(time.time())
        if user["lockout_until"] and now < user["lockout_until"]:
            remaining = user["lockout_until"] - now
            flash(f"Account locked. Try again in {remaining} seconds.")
            return redirect(url_for("login"))

        ok = bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8"))
        if not ok:
            failed = user["failed_attempts"] + 1
            lockout_until = user["lockout_until"]
            msg = "Invalid username or password."

            if failed >= FAILED_LIMIT:
                lockout_until = now + LOCK_MINUTES * 60
                msg = f"Too many failures. Account locked for {LOCK_MINUTES} minutes."

            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET failed_attempts=?, lockout_until=? WHERE id=?",
                    (failed, lockout_until, user["id"]),
                )

            flash(msg)
            return redirect(url_for("login"))

        with get_db() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts=0, lockout_until=0 WHERE id=?",
                (user["id"],),
            )

        if user["totp_enabled"]:
            session["pending_2fa_user_id"] = user["id"]
            return redirect(url_for("verify_2fa"))

        session["user_id"] = user["id"]
        flash("Logged in without 2FA.")
        return redirect(url_for("dashboard"))

    return page("Login", """
        <form method="post">
          <label>Username</label>
          <input name="username" required>
          <label>Password</label>
          <input name="password" type="password" required>
          <button type="submit">Login</button>
        </form>
        <p><a href="/register">Register</a></p>
    """)

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_2fa_user_id")
    if not uid:
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    totp = pyotp.TOTP(user["totp_secret"])

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        counter = current_counter()

        if counter <= user["last_totp_counter"]:
            flash("Replay rejected. Use a fresh OTP.")
            return redirect(url_for("verify_2fa"))

        if totp.verify(otp, valid_window=1):
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET last_totp_counter=? WHERE id=?",
                    (counter, uid),
                )
            session.pop("pending_2fa_user_id", None)
            session["user_id"] = uid
            flash("2FA success.")
            return redirect(url_for("dashboard"))

        flash("Wrong OTP.")
        return redirect(url_for("verify_2fa"))

    return page("2FA Verification", """
        <form method="post">
          <label>OTP</label>
          <input name="otp" inputmode="numeric" required>
          <button type="submit">Verify</button>
        </form>
    """)

@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    return page("Dashboard", f"""
        <p>Welcome, <strong>{user["username"]}</strong>.</p>
        <p>2FA enabled: <strong>{'yes' if user['totp_enabled'] else 'no'}</strong></p>
        <p><a href="/logout">Logout</a></p>
        <hr>
        <p>To prove hashes in DB, run:</p>
        <pre>sqlite3 auth.db "SELECT username, password_hash FROM users;"</pre>
    """)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)

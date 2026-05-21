"""
Web Application - Login System
================================
Flask app sederhana untuk simulasi sistem login.
App ini TIDAK tahu soal enkripsi — semua enkripsi dihandle oleh Gateway.
App ini hanya menerima plain JSON dari Gateway di internal Docker network.
"""

import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path

from flask import Flask, g, jsonify, request

app = Flask(__name__)

DB_PATH = "/data/users.db"
Path("/data").mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at  INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            username    TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS login_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT,
            success     INTEGER,
            ip          TEXT,
            timestamp   INTEGER
        )
    """)
    db.commit()

    # Seed: buat user demo jika belum ada
    cur = db.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cur.fetchone():
        pw_hash = _hash_password("admin123")
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", pw_hash, int(time.time())),
        )
        pw_hash2 = _hash_password("user123")
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("alice", pw_hash2, int(time.time())),
        )
        db.commit()

    db.close()


def _hash_password(password: str) -> str:
    """Hash password dengan SHA-256 + salt."""
    salt = "ascon_demo_salt_v1"  # production: gunakan bcrypt / argon2
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "webapp"})


@app.route("/auth/register", methods=["POST"])
def register():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username dan password wajib diisi"}), 400

    if len(username) < 3 or len(username) > 32:
        return jsonify({"success": False, "message": "Username harus 3-32 karakter"}), 400

    if len(password) < 6:
        return jsonify({"success": False, "message": "Password minimal 6 karakter"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, _hash_password(password), int(time.time())),
        )
        db.commit()
        return jsonify({"success": True, "message": f"User '{username}' berhasil dibuat"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username sudah digunakan"}), 409


@app.route("/auth/login", methods=["POST"])
def login():
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user or user["password_hash"] != _hash_password(password):
        db.execute(
            "INSERT INTO login_log (username, success, ip, timestamp) VALUES (?, 0, ?, ?)",
            (username, request.remote_addr, int(time.time())),
        )
        db.commit()
        return jsonify({"success": False, "message": "Username atau password salah"}), 401

    # Buat session token
    token      = secrets.token_hex(32)
    expires_at = int(time.time()) + 3600  # 1 jam

    db.execute(
        "INSERT INTO sessions (token, user_id, username, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (token, user["id"], username, int(time.time()), expires_at),
    )
    db.execute(
        "INSERT INTO login_log (username, success, ip, timestamp) VALUES (?, 1, ?, ?)",
        (username, request.remote_addr, int(time.time())),
    )
    db.commit()

    return jsonify({
        "success":    True,
        "message":    f"Login berhasil, selamat datang {username}!",
        "token":      token,
        "expires_at": expires_at,
        "user": {
            "id":       user["id"],
            "username": username,
        },
    })


@app.route("/auth/logout", methods=["POST"])
def logout():
    data  = request.json or {}
    token = data.get("token", "")

    db = get_db()
    db.execute("DELETE FROM sessions WHERE token = ?", (token,))
    db.commit()
    return jsonify({"success": True, "message": "Logout berhasil"})


@app.route("/auth/verify", methods=["POST"])
def verify():
    data  = request.json or {}
    token = data.get("token", "")

    db = get_db()
    session = db.execute(
        "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
        (token, int(time.time())),
    ).fetchone()

    if not session:
        return jsonify({"valid": False, "message": "Token tidak valid atau sudah kadaluarsa"}), 401

    return jsonify({
        "valid":    True,
        "username": session["username"],
        "user_id":  session["user_id"],
    })


@app.route("/auth/profile", methods=["POST"])
def profile():
    data  = request.json or {}
    token = data.get("token", "")

    db = get_db()
    session = db.execute(
        "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
        (token, int(time.time())),
    ).fetchone()

    if not session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    logs = db.execute(
        "SELECT * FROM login_log WHERE username = ? ORDER BY timestamp DESC LIMIT 5",
        (session["username"],),
    ).fetchall()

    return jsonify({
        "success":  True,
        "username": user["username"],
        "user_id":  user["id"],
        "login_history": [
            {"success": bool(l["success"]), "timestamp": l["timestamp"]}
            for l in logs
        ],
    })


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)

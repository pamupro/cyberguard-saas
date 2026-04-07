"""
CyberGuard – Authentication utilities
SQLite-backed user store with bcrypt password hashing.
Falls back to PBKDF2-HMAC-SHA256 (stdlib) if bcrypt is unavailable.
"""

import hashlib
import os
import sqlite3
from contextlib import closing
from datetime import datetime

# Prefer bcrypt; fall back to stdlib PBKDF2 so the app always starts.
try:
    import bcrypt as _bcrypt
    _USE_BCRYPT = True
except ImportError:
    _bcrypt = None          # type: ignore
    _USE_BCRYPT = False

DB_FILE = "cyberguard.db"


# ---------------------------------------------------------------------------
# DB bootstrap
# ---------------------------------------------------------------------------

def init_db() -> None:
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT    NOT NULL,
                email         TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL
            )
            """
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Helpers  (bcrypt preferred; PBKDF2 fallback)
# ---------------------------------------------------------------------------

def _hash(password: str) -> str:
    if _USE_BCRYPT:
        return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()
    # PBKDF2 fallback: "pbkdf2$<hex-salt>$<hex-dk>"
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def _verify(password: str, stored: str) -> bool:
    try:
        if stored.startswith("pbkdf2$"):
            _, salt_hex, dk_hex = stored.split("$")
            salt = bytes.fromhex(salt_hex)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
            return dk.hex() == dk_hex
        # bcrypt hash
        if _USE_BCRYPT:
            return _bcrypt.checkpw(password.encode(), stored.encode())
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_user(name: str, email: str, password: str) -> tuple[bool, str]:
    try:
        with closing(sqlite3.connect(DB_FILE)) as conn:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name.strip(), email.strip().lower(), _hash(password), datetime.utcnow().isoformat()),
            )
            conn.commit()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "That email address is already registered."
    except Exception as exc:
        return False, f"Unexpected error: {exc}"


def authenticate_user(email: str, password: str) -> tuple[bool, dict | None]:
    with closing(sqlite3.connect(DB_FILE)) as conn:
        row = conn.execute(
            "SELECT id, name, email, password_hash FROM users WHERE email = ?",
            (email.strip().lower(),),
        ).fetchone()
    if row and _verify(password, row[3]):
        return True, {"id": row[0], "name": row[1], "email": row[2]}
    return False, None

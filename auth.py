"""
CyberGuard - Authentication utilities
SQLite-backed user store. Uses PBKDF2-HMAC-SHA256 (Python stdlib only).
No third-party packages required.
"""

import hashlib
import os
import sqlite3
from contextlib import closing
from datetime import datetime

DB_FILE = "cyberguard.db"


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


def _hash(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def _verify(password: str, stored: str) -> bool:
    try:
        _, salt_hex, dk_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
        return dk.hex() == dk_hex
    except Exception:
        return False


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

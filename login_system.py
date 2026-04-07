"""
login_system.py — Production-grade password authentication system

Integrates every concept from the series:
  hash.py          → bcrypt as the baseline hasher
  rainbow_table.py → salting defeats precomputed lookup
  brute_force.py   → cost factor slows exhaustive search
  timing_attack.py → constant-time comparison everywhere
  salt_deep.py     → per-user random salts, embedded in bcrypt
  cost_factor.py   → configurable rounds, OWASP-aligned defaults
  pepper.py        → HMAC pepper stored outside the database
  upgrade_strategy.py → lazy hash migration on login

Public API
----------
  LoginSystem(config)          — construct with a Config object
  system.register(user, pw)    — create account
  system.login(user, pw)       → LoginResult
  system.change_password(...)  → bool
  system.get_user(user)        → UserRecord | None
  system.list_users()          → list[str]
  system.scheme_stats()        → dict[str, int]
"""

from __future__ import annotations

import bcrypt
import hashlib
import hmac
import os
import time
import sqlite3
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("login_system")


# ── Configuration ─────────────────────────────────────────────────────────────

@dataclass
class Config:
    """
    All tuneable knobs for the system in one place.

    bcrypt_rounds     — cost factor; each +1 doubles hash time
                        OWASP minimum: 10, recommended: 12
    pepper            — 32-byte secret; load from env in production
    db_path           — SQLite path; use ":memory:" for tests
    max_login_attempts— lockout threshold
    lockout_seconds   — how long to lock an account after threshold
    min_password_len  — validated on register and change_password
    max_password_len  — bcrypt truncates at 72 bytes; we enforce this
    """
    bcrypt_rounds: int   = 12
    pepper: bytes        = field(default_factory=lambda: os.urandom(32))
    db_path: str         = ":memory:"
    max_login_attempts: int = 5
    lockout_seconds: int    = 300        # 5 minutes
    min_password_len: int   = 8
    max_password_len: int   = 72


# ── Hash schemes (same generation ladder as upgrade_strategy.py) ──────────────

class Scheme(str, Enum):
    MD5_PLAIN      = "md5_plain"       # gen 0 — legacy import only
    SHA256_SALTED  = "sha256_salted"   # gen 1 — legacy import only
    BCRYPT_8       = "bcrypt_8"        # gen 2 — legacy import only
    BCRYPT_12      = "bcrypt_12"       # gen 3 — acceptable baseline
    BCRYPT_PEPPER  = "bcrypt_pepper"   # gen 4 — current target


SCHEME_GENERATION: dict[Scheme, int] = {
    Scheme.MD5_PLAIN:     0,
    Scheme.SHA256_SALTED: 1,
    Scheme.BCRYPT_8:      2,
    Scheme.BCRYPT_12:     3,
    Scheme.BCRYPT_PEPPER: 4,
}

CURRENT_SCHEME = Scheme.BCRYPT_PEPPER


# ── User record ───────────────────────────────────────────────────────────────

@dataclass
class UserRecord:
    username:        str
    scheme:          str
    password_hash:   str
    failed_attempts: int   = 0
    locked_until:    float = 0.0
    created_at:      float = field(default_factory=time.time)
    last_login_at:   float = 0.0
    pepper_version:  int   = 1


# ── Login result ──────────────────────────────────────────────────────────────

@dataclass
class LoginResult:
    success:        bool
    message:        str
    hash_upgraded:  bool  = False
    old_scheme:     str   = ""
    new_scheme:     str   = ""
    elapsed_ms:     float = 0.0


# ── Core crypto helpers ───────────────────────────────────────────────────────

def _validate_password(password: str, min_len: int = 8, max_len: int = 72) -> None:
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    if len(password) < min_len:
        raise ValueError(f"Password must be at least {min_len} characters.")
    if len(password) > max_len:
        raise ValueError(f"Password exceeds {max_len}-character limit.")


def _hmac_pepper(password: str, pepper: bytes) -> str:
    """HMAC-SHA256(password, pepper) → 64-char hex string safe for bcrypt."""
    return hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).hexdigest()


def _hash_bcrypt_pepper(password: str, pepper: bytes, rounds: int) -> str:
    peppered = _hmac_pepper(password, pepper)
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(peppered.encode("utf-8"), salt).decode("utf-8")


def _verify_bcrypt_pepper(password: str, stored: str, pepper: bytes) -> bool:
    peppered = _hmac_pepper(password, pepper)
    return bcrypt.checkpw(peppered.encode("utf-8"), stored.encode("utf-8"))


def _hash_bcrypt_plain(password: str, rounds: int) -> str:
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def _verify_bcrypt_plain(password: str, stored: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))


def _verify_md5_plain(password: str, stored: str) -> bool:
    candidate = hashlib.md5(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, stored)


def _verify_sha256_salted(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split(":", 1)
    except ValueError:
        return False
    candidate = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, digest)


# ── Database layer ────────────────────────────────────────────────────────────

class _Database:
    """Thin SQLite wrapper. Swap for your ORM in production."""

    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username        TEXT PRIMARY KEY,
                scheme          TEXT NOT NULL,
                password_hash   TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    REAL    NOT NULL DEFAULT 0,
                created_at      REAL    NOT NULL,
                last_login_at   REAL    NOT NULL DEFAULT 0,
                pepper_version  INTEGER NOT NULL DEFAULT 1
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS upgrade_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT NOT NULL,
                old_scheme TEXT NOT NULL,
                new_scheme TEXT NOT NULL,
                upgraded_at REAL NOT NULL
            )
        """)
        self._conn.commit()

    def fetch(self, username: str) -> UserRecord | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return None
        return UserRecord(**dict(row))

    def insert(self, rec: UserRecord) -> None:
        self._conn.execute(
            """INSERT INTO users
               (username, scheme, password_hash, failed_attempts, locked_until,
                created_at, last_login_at, pepper_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (rec.username, rec.scheme, rec.password_hash, rec.failed_attempts,
             rec.locked_until, rec.created_at, rec.last_login_at, rec.pepper_version),
        )
        self._conn.commit()

    def update_hash(self, username: str, scheme: str, password_hash: str,
                    pepper_version: int) -> None:
        self._conn.execute(
            "UPDATE users SET scheme=?, password_hash=?, pepper_version=? WHERE username=?",
            (scheme, password_hash, pepper_version, username),
        )
        self._conn.commit()

    def record_success(self, username: str) -> None:
        self._conn.execute(
            "UPDATE users SET failed_attempts=0, locked_until=0, last_login_at=? WHERE username=?",
            (time.time(), username),
        )
        self._conn.commit()

    def record_failure(self, username: str, attempts: int,
                       locked_until: float) -> None:
        self._conn.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
            (attempts, locked_until, username),
        )
        self._conn.commit()

    def log_upgrade(self, username: str, old_scheme: str, new_scheme: str) -> None:
        self._conn.execute(
            "INSERT INTO upgrade_log (username, old_scheme, new_scheme, upgraded_at) VALUES (?,?,?,?)",
            (username, old_scheme, new_scheme, time.time()),
        )
        self._conn.commit()

    def all_usernames(self) -> list[str]:
        rows = self._conn.execute("SELECT username FROM users ORDER BY username").fetchall()
        return [r["username"] for r in rows]

    def scheme_counts(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT scheme, COUNT(*) AS n FROM users GROUP BY scheme"
        ).fetchall()
        return {r["scheme"]: r["n"] for r in rows}

    def upgrade_log_entries(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM upgrade_log ORDER BY upgraded_at"
        ).fetchall()
        return [dict(r) for r in rows]


# ── Login system ──────────────────────────────────────────────────────────────

class LoginSystem:
    """
    Thread-safe authentication system with:
      - bcrypt + HMAC pepper hashing (gen 4)
      - Lazy hash upgrade on login (gen 0-3 → gen 4)
      - Account lockout after repeated failures
      - Constant-time password comparison (via bcrypt.checkpw)
      - Dummy bcrypt work on unknown usernames (timing-safe)
    """

    def __init__(self, config: Config | None = None):
        self._cfg = config or Config()
        self._db  = _Database(self._cfg.db_path)
        log.info("LoginSystem initialised  rounds=%d  db=%s",
                 self._cfg.bcrypt_rounds, self._cfg.db_path)

    # ── Public API ────────────────────────────────────────────────

    def register(self, username: str, password: str) -> None:
        """
        Creates a new account hashed with the current best scheme.
        Raises ValueError on bad input or duplicate username.
        """
        if not username or not username.strip():
            raise ValueError("Username cannot be empty.")
        username = username.strip().lower()

        _validate_password(password, self._cfg.min_password_len,
                           self._cfg.max_password_len)

        if self._db.fetch(username) is not None:
            raise ValueError(f"Username '{username}' is already taken.")

        pw_hash = _hash_bcrypt_pepper(
            password, self._cfg.pepper, self._cfg.bcrypt_rounds
        )
        rec = UserRecord(
            username=username,
            scheme=CURRENT_SCHEME.value,
            password_hash=pw_hash,
        )
        self._db.insert(rec)
        log.info("register  user=%s  scheme=%s", username, CURRENT_SCHEME.value)

    def login(self, username: str, password: str) -> LoginResult:
        """
        Authenticates a user. On success, transparently upgrades legacy hashes.
        Returns a LoginResult with full details.
        """
        t0 = time.perf_counter()
        username = username.strip().lower()

        rec = self._db.fetch(username)

        # Unknown user — do dummy work to prevent timing-based enumeration
        if rec is None:
            _hash_bcrypt_pepper("__dummy__", self._cfg.pepper, self._cfg.bcrypt_rounds)
            elapsed = (time.perf_counter() - t0) * 1000
            log.warning("login_fail  user=%s  reason=unknown_user", username)
            return LoginResult(False, "Invalid username or password.", elapsed_ms=elapsed)

        # Account lockout check
        if rec.locked_until > time.time():
            remaining = int(rec.locked_until - time.time())
            elapsed = (time.perf_counter() - t0) * 1000
            log.warning("login_fail  user=%s  reason=locked  remaining=%ds", username, remaining)
            return LoginResult(False,
                               f"Account locked. Try again in {remaining}s.",
                               elapsed_ms=elapsed)

        # Verify password against stored scheme
        verified = self._verify(password, rec)

        if not verified:
            new_attempts = rec.failed_attempts + 1
            locked_until = 0.0
            if new_attempts >= self._cfg.max_login_attempts:
                locked_until = time.time() + self._cfg.lockout_seconds
                log.warning("login_fail  user=%s  reason=bad_password  LOCKED", username)
            else:
                remaining_attempts = self._cfg.max_login_attempts - new_attempts
                log.warning("login_fail  user=%s  reason=bad_password  attempts=%d",
                            username, new_attempts)
            self._db.record_failure(username, new_attempts, locked_until)
            elapsed = (time.perf_counter() - t0) * 1000
            return LoginResult(False, "Invalid username or password.", elapsed_ms=elapsed)

        # Password is correct — check for hash upgrade
        old_scheme = rec.scheme
        upgraded   = False

        if rec.scheme != CURRENT_SCHEME.value:
            new_hash = _hash_bcrypt_pepper(
                password, self._cfg.pepper, self._cfg.bcrypt_rounds
            )
            self._db.update_hash(username, CURRENT_SCHEME.value, new_hash, 1)
            self._db.log_upgrade(username, old_scheme, CURRENT_SCHEME.value)
            upgraded = True
            log.info("hash_upgrade  user=%s  %s → %s", username, old_scheme, CURRENT_SCHEME.value)

        self._db.record_success(username)
        elapsed = (time.perf_counter() - t0) * 1000
        log.info("login_ok  user=%s  scheme=%s  upgraded=%s  elapsed=%.0fms",
                 username, rec.scheme, upgraded, elapsed)

        msg = "Login successful."
        if upgraded:
            msg += f" (hash upgraded: {old_scheme} → {CURRENT_SCHEME.value})"

        return LoginResult(
            success=True,
            message=msg,
            hash_upgraded=upgraded,
            old_scheme=old_scheme if upgraded else "",
            new_scheme=CURRENT_SCHEME.value if upgraded else "",
            elapsed_ms=elapsed,
        )

    def change_password(self, username: str, old_password: str,
                        new_password: str) -> bool:
        """
        Changes a user's password after verifying the old one.
        Always upgrades to the current scheme.
        """
        username = username.strip().lower()
        rec = self._db.fetch(username)
        if rec is None:
            return False

        if not self._verify(old_password, rec):
            log.warning("change_password_fail  user=%s  reason=bad_old_password", username)
            return False

        _validate_password(new_password, self._cfg.min_password_len,
                           self._cfg.max_password_len)

        new_hash = _hash_bcrypt_pepper(
            new_password, self._cfg.pepper, self._cfg.bcrypt_rounds
        )
        self._db.update_hash(username, CURRENT_SCHEME.value, new_hash, 1)
        log.info("change_password_ok  user=%s", username)
        return True

    def get_user(self, username: str) -> UserRecord | None:
        return self._db.fetch(username.strip().lower())

    def list_users(self) -> list[str]:
        return self._db.all_usernames()

    def scheme_stats(self) -> dict[str, int]:
        return self._db.scheme_counts()

    def upgrade_log(self) -> list[dict]:
        return self._db.upgrade_log_entries()

    # ── Legacy import ─────────────────────────────────────────────

    def import_legacy_user(self, username: str, scheme: str,
                           stored_hash: str) -> None:
        """
        Imports a user whose password was hashed under a legacy scheme.
        The hash will be upgraded to the current scheme on their first login.
        """
        username = username.strip().lower()
        if self._db.fetch(username) is not None:
            raise ValueError(f"User '{username}' already exists.")

        allowed = {s.value for s in Scheme}
        if scheme not in allowed:
            raise ValueError(f"Unknown scheme '{scheme}'.")

        rec = UserRecord(
            username=username,
            scheme=scheme,
            password_hash=stored_hash,
        )
        self._db.insert(rec)
        log.info("import_legacy  user=%s  scheme=%s", username, scheme)

    # ── Private helpers ───────────────────────────────────────────

    def _verify(self, password: str, rec: UserRecord) -> bool:
        """Dispatches to the correct verify function for the stored scheme."""
        try:
            scheme = Scheme(rec.scheme)
        except ValueError:
            log.error("unknown_scheme  user=%s  scheme=%s", rec.username, rec.scheme)
            return False

        if scheme == Scheme.BCRYPT_PEPPER:
            return _verify_bcrypt_pepper(password, rec.password_hash, self._cfg.pepper)
        elif scheme in (Scheme.BCRYPT_12, Scheme.BCRYPT_8):
            return _verify_bcrypt_plain(password, rec.password_hash)
        elif scheme == Scheme.SHA256_SALTED:
            return _verify_sha256_salted(password, rec.password_hash)
        elif scheme == Scheme.MD5_PLAIN:
            return _verify_md5_plain(password, rec.password_hash)
        return False
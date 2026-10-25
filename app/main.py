"""AuthGuard: small FastAPI example with server-side sessions and RBAC."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Iterator

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict


ROOT = Path(__file__).resolve().parent.parent
PAGES = ROOT / "app" / "pages"
load_dotenv(ROOT / ".env")

database_setting = Path(os.getenv("AUTHGUARD_DB_PATH", "data/authguard.db"))
DATABASE_PATH = database_setting if database_setting.is_absolute() else ROOT / database_setting
COOKIE_NAME = "authguard_session"
COOKIE_SECURE = os.getenv("AUTHGUARD_SECURE_COOKIE", "0") == "1"
SESSION_SECONDS = 60 * 60 * 8
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MAX_FAILED_LOGINS = 5
LOGIN_WINDOW_SECONDS = 60
LOGIN_COOLDOWN_SECONDS = 30

# Argon2id settings meet the OWASP minimum: 19 MiB, two passes, one lane.
PASSWORD_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
# A nonexistent username still causes a normal password-hash verification.
DUMMY_HASH = PASSWORD_HASHER.hash("ThisIsNotAnActualUserPassword")


class Credentials(BaseModel):
    # Reject unexpected fields, including attempts to supply role="admin".
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_database() -> None:
    with database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                failed_count INTEGER NOT NULL,
                window_started_at INTEGER NOT NULL,
                blocked_until INTEGER NOT NULL DEFAULT 0
            );
            """
        )


def validate_new_account(username: str, password: str) -> str:
    normalized = username.strip().lower()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError("Username must be 3-32 letters, numbers, dots, dashes or underscores.")
    if not 8 <= len(password) <= 128 or not password.strip():
        raise ValueError("Password must be 8-128 characters and cannot be blank.")
    return normalized


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def login_retry_after(username: str) -> int:
    """Seconds remaining on a temporary block; zero means login may proceed."""
    now = int(time.time())
    with database() as connection:
        row = connection.execute(
            "SELECT blocked_until FROM login_attempts WHERE username = ?", (username,)
        ).fetchone()
    return max(0, row["blocked_until"] - now) if row else 0


def record_failed_login(username: str) -> int:
    """Count failures atomically and return a cooldown when the limit is reached."""
    now = int(time.time())
    with database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM login_attempts WHERE blocked_until <= ? AND window_started_at <= ?",
            (now, now - LOGIN_WINDOW_SECONDS),
        )
        row = connection.execute(
            "SELECT failed_count, window_started_at, blocked_until "
            "FROM login_attempts WHERE username = ?",
            (username,),
        ).fetchone()
        if row and row["blocked_until"] > now:
            return row["blocked_until"] - now

        if not row or row["blocked_until"] or now - row["window_started_at"] >= LOGIN_WINDOW_SECONDS:
            failed_count, window_started = 1, now
        else:
            failed_count, window_started = row["failed_count"] + 1, row["window_started_at"]
        blocked_until = now + LOGIN_COOLDOWN_SECONDS if failed_count >= MAX_FAILED_LOGINS else 0
        connection.execute(
            """INSERT INTO login_attempts (username, failed_count, window_started_at, blocked_until)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET
                 failed_count=excluded.failed_count,
                 window_started_at=excluded.window_started_at,
                 blocked_until=excluded.blocked_until""",
            (username, failed_count, window_started, blocked_until),
        )
    return max(0, blocked_until - now)


def too_many_logins(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail=f"Too many failed login attempts. Try again in {retry_after} seconds.",
        headers={"Retry-After": str(retry_after)},
    )


def session_token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def require_user(request: Request) -> dict:
    raw_token = request.cookies.get(COOKIE_NAME)
    if not raw_token:
        raise HTTPException(status_code=401, detail="Authentication required")
    with database() as connection:
        row = connection.execute(
            """
            SELECT users.id, users.username, users.role
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """,
            (session_token_hash(raw_token), int(time.time())),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return dict(row)


def require_admin(user: dict = Depends(require_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_database()
    yield


app = FastAPI(title="AuthGuard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")


@app.middleware("http")
async def response_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(PAGES / "index.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard(_: dict = Depends(require_user)):
    return FileResponse(PAGES / "dashboard.html")


@app.get("/admin", include_in_schema=False)
def admin_page(_: dict = Depends(require_admin)):
    return FileResponse(PAGES / "admin.html")


@app.post("/api/register", status_code=201)
def register(credentials: Credentials):
    try:
        username = validate_new_account(credentials.username, credentials.password)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    with database() as connection:
        try:
            connection.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                (username, hash_password(credentials.password)),
            )
        except sqlite3.IntegrityError as error:
            raise HTTPException(status_code=409, detail="Username unavailable") from error
    return {"message": "Account created. You can log in now."}


@app.post("/api/login")
def login(credentials: Credentials, request: Request):
    username = credentials.username.strip().lower()
    retry_after = login_retry_after(username)
    if retry_after:
        raise too_many_logins(retry_after)
    with database() as connection:
        user = connection.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    saved_hash = user["password_hash"] if user else DUMMY_HASH
    valid_password = verify_password(saved_hash, credentials.password)
    if not user or not valid_password:
        retry_after = record_failed_login(username)
        if retry_after:
            raise too_many_logins(retry_after)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    old_token = request.cookies.get(COOKIE_NAME)
    token = secrets.token_urlsafe(32)
    with database() as connection:
        connection.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
        if old_token:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (session_token_hash(old_token),),
            )
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (session_token_hash(token), user["id"], int(time.time()) + SESSION_SECONDS),
        )

    response = JSONResponse({"message": "Logged in", "username": user["username"], "role": user["role"]})
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_SECONDS,
        path="/",
    )
    return response


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        with database() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (session_token_hash(token),))
    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie(key=COOKIE_NAME, path="/", secure=COOKIE_SECURE, httponly=True, samesite="lax")
    return response


@app.get("/api/user")
def user_data(user: dict = Depends(require_user)):
    return {"message": "User dashboard access granted", "username": user["username"], "role": user["role"]}


@app.get("/api/admin")
def admin_data(user: dict = Depends(require_admin)):
    with database() as connection:
        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return {"message": "Admin access granted", "username": user["username"], "user_count": user_count}


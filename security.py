import hmac
import secrets
import time

from fastapi import HTTPException, Request


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token

    return token


def verify_csrf_token(request: Request, submitted_token: str):
    expected_token = request.session.get("csrf_token")

    if (
        not expected_token
        or not submitted_token
        or not hmac.compare_digest(expected_token, submitted_token)
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid security token. Refresh the page and try again."
        )


def login_is_locked(db, username: str) -> bool:
    key = username.strip().casefold()
    now = int(time.time())

    row = db.execute(
        "SELECT locked_until FROM login_attempts WHERE username = ?",
        (key,)
    ).fetchone()

    return bool(row and row["locked_until"] > now)


def record_failed_login(db, username: str):
    key = username.strip().casefold()
    now = int(time.time())

    row = db.execute(
        """
        SELECT attempts, window_started_at
        FROM login_attempts
        WHERE username = ?
        """,
        (key,)
    ).fetchone()

    if not row or now - row["window_started_at"] >= 900:
        attempts = 1
        window_started = now
    else:
        attempts = row["attempts"] + 1
        window_started = row["window_started_at"]

    locked_until = now + 900 if attempts >= 5 else 0

    db.execute(
        """
        INSERT INTO login_attempts
            (username, attempts, window_started_at, locked_until)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            attempts = excluded.attempts,
            window_started_at = excluded.window_started_at,
            locked_until = excluded.locked_until
        """,
        (key, attempts, window_started, locked_until)
    )


def clear_login_attempts(db, username: str):
    key = username.strip().casefold()

    db.execute(
        "DELETE FROM login_attempts WHERE username = ?",
        (key,)
    )
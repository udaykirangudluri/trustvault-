import os
import html
import sqlite3

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from database import get_db, init_db
from auth import hash_password, verify_password
from security import (
    get_csrf_token,
    verify_csrf_token,
    login_is_locked,
    record_failed_login,
    clear_login_attempts,
)


# Require a private session secret from the environment.
SESSION_SECRET = os.environ.get("TRUSTVAULT_SECRET")

if not SESSION_SECRET:
    raise RuntimeError(
        "TRUSTVAULT_SECRET is missing. "
        "Generate a secret and export it before starting TrustVault."
    )


app = FastAPI(
    title="TrustVault DMS",
    description="Secure Document Management System",
    version="1.0.0"
)


app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True
)


init_db()

from documents import router as documents_router
app.include_router(documents_router)

from audit import router as audit_router
app.include_router(audit_router)


def page(title, content):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{html.escape(title)} - TrustVault</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f1f5f9;
                margin: 0;
                padding: 35px 15px;
            }}
            .card {{
                background: white;
                max-width: 420px;
                margin: 35px auto;
                padding: 28px;
                border-radius: 12px;
                box-shadow: 0 4px 15px #0001;
            }}
            h1 {{
                color: #173b70;
                text-align: center;
            }}
            h2 {{
                text-align: center;
            }}
            input, button {{
                width: 100%;
                padding: 12px;
                margin: 9px 0;
                box-sizing: border-box;
                border-radius: 6px;
            }}
            input {{
                border: 1px solid #cbd5e1;
            }}
            button {{
                background: #173b70;
                color: white;
                border: none;
                cursor: pointer;
            }}
            button:hover {{
                background: #24569a;
            }}
            a {{
                color: #173b70;
            }}
            .message {{
                color: #b42318;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>TrustVault</h1>
            {content}
        </div>
    </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)

    content = """
        <h2>Secure Document Management System</h2>
        <p style="text-align:center;">
            Protecting your confidential documents.
        </p>
        <p><a href="/register">Create an account</a></p>
        <p><a href="/login">Sign in</a></p>
    """

    return page("Home", content)


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    token = get_csrf_token(request)

    content = f"""
        <h2>Create Account</h2>
        <form method="post" action="/register">
            <input type="hidden" name="csrf_token"
                   value="{html.escape(token, quote=True)}">

            <input name="username"
                   placeholder="Username"
                   minlength="3" maxlength="40" required>

            <input name="password"
                   type="password"
                   placeholder="Password (minimum 12 characters)"
                   minlength="12" required>

            <button type="submit">Register</button>
        </form>
        <p>Already registered? <a href="/login">Sign in</a></p>
    """

    return page("Register", content)


@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...)
):
    verify_csrf_token(request, csrf_token)

    username = username.strip()

    if not 3 <= len(username) <= 40:
        return page(
            "Register",
            '<p class="message">Username must be between 3 and 40 characters.</p>'
            '<a href="/register">Try again</a>'
        )

    if len(password) < 12:
        return page(
            "Register",
            '<p class="message">Password must contain at least 12 characters.</p>'
            '<a href="/register">Try again</a>'
        )

    db = get_db()

    try:
        db.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username, hash_password(password), "viewer")
        )
        db.commit()

    except sqlite3.IntegrityError:
        return page(
            "Register",
            '<p class="message">This username already exists.</p>'
            '<a href="/register">Try again</a>'
        )

    finally:
        db.close()

    return page(
        "Registered",
        """
        <h2>Registration Successful!</h2>
        <p>Your account has been created.</p>
        <p>Your initial role is Viewer.</p>
        <a href="/login">Sign in now</a>
        """
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = get_csrf_token(request)

    content = f"""
        <h2>Sign In</h2>
        <form method="post" action="/login">
            <input type="hidden" name="csrf_token"
                   value="{html.escape(token, quote=True)}">

            <input name="username" placeholder="Username" required>
            <input name="password" type="password"
                   placeholder="Password" required>

            <button type="submit">Login</button>
        </form>
        <p>New user? <a href="/register">Create account</a></p>
    """

    return page("Login", content)


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...)
):
    verify_csrf_token(request, csrf_token)

    username = username.strip()
    db = get_db()

    try:
        if login_is_locked(db, username):
            return page(
                "Login",
                """
                <p class="message">
                    Too many failed attempts. Please try again after 15 minutes.
                </p>
                <a href="/login">Return to login</a>
                """
            )

        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if not user or not verify_password(
            password,
            user["password_hash"]
        ):
            record_failed_login(db, username)
            db.commit()

            return page(
                "Login",
                """
                <p class="message">Invalid username or password.</p>
                <a href="/login">Try again</a>
                """
            )

        clear_login_attempts(db, username)
        db.commit()

    finally:
        db.close()

    request.session.clear()
    request.session["user_id"] = user["id"]

    return RedirectResponse("/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    db = get_db()

    try:
        user = db.execute(
            "SELECT username, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    finally:
        db.close()

    if not user:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    username = html.escape(user["username"])
    role = html.escape(user["role"].title())
    token = get_csrf_token(request)

    content = f"""
        <h2>Welcome, {username}!</h2>
        <p>Your role: <strong>{role}</strong></p>
        <p>You are signed in to TrustVault.</p>
        <p><a href="/documents">Manage Documents</a></p>
        <p><a href="/audit">View Audit Logs (Administrators)</a></p>

        <form method="post" action="/logout">
            <input type="hidden" name="csrf_token"
                   value="{html.escape(token, quote=True)}">
            <button type="submit">Logout</button>
        </form>
    """

    return page("Dashboard", content)


@app.post("/logout")
async def logout(
    request: Request,
    csrf_token: str = Form(...)
):
    verify_csrf_token(request, csrf_token)
    request.session.clear()

    return RedirectResponse("/", status_code=303)


@app.get("/health")
async def health():
    return {
        "status": "running",
        "platform": "TrustVault"
    }
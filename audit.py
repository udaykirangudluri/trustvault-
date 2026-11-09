import html

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from database import get_db

router = APIRouter()


@router.get("/audit", response_class=HTMLResponse)
async def view_audit_logs(request: Request):

    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    db = get_db()

    try:
        user = db.execute(
            "SELECT role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not user or user["role"] != "admin":
            raise HTTPException(
                status_code=403,
                detail="Administrator access required"
            )

        logs = db.execute("""
            SELECT
                audit_logs.action,
                audit_logs.details,
                audit_logs.created_at,
                users.username,
                documents.filename
            FROM audit_logs
            LEFT JOIN users
                ON audit_logs.actor_id = users.id
            LEFT JOIN documents
                ON audit_logs.document_id = documents.id
            ORDER BY audit_logs.id DESC
        """).fetchall()

    finally:
        db.close()

    rows = ""

    for log in logs:
        username = html.escape(log["username"] or "Unknown")
        action = html.escape(log["action"] or "N/A")
        document = html.escape(
            log["filename"] or log["details"] or "N/A"
        )
        created_at = html.escape(log["created_at"] or "N/A")

        rows += f"""
        <tr>
            <td>{username}</td>
            <td>{action}</td>
            <td>{document}</td>
            <td>{created_at}</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>TrustVault Audit Logs</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                font-family: Arial, sans-serif;
                padding: 20px;
                background: #f1f5f9;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                background: white;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
                overflow-wrap: anywhere;
            }}
            th {{
                background: #173b70;
                color: white;
            }}
            a {{
                color: #173b70;
            }}
        </style>
    </head>
    <body>
        <h1>TrustVault Audit Logs</h1>
        <table>
            <tr>
                <th>User</th>
                <th>Action</th>
                <th>Document</th>
                <th>Date and Time</th>
            </tr>
            {rows}
        </table>
        <p><a href="/dashboard">Back to Dashboard</a></p>
    </body>
    </html>
    """
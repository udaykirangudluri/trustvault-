import html
import io
import uuid
import zipfile
from pathlib import Path

from fastapi import (
    APIRouter, Request, UploadFile, File,
    HTTPException, Form
)
from fastapi.responses import (
    HTMLResponse, FileResponse, RedirectResponse
)

from database import get_db
from security import get_csrf_token, verify_csrf_token

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent
PRIVATE_DIR = BASE_DIR / "storage" / "private"
PRIVATE_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".txt"}


def document_page(content):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Documents - TrustVault</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f1f5f9;
                padding: 25px 15px;
            }}
            .card {{
                background: white;
                max-width: 650px;
                margin: 25px auto;
                padding: 25px;
                border-radius: 12px;
                box-shadow: 0 4px 15px #0001;
            }}
            h1 {{ color: #173b70; }}
            input, button {{
                padding: 12px;
                margin: 10px 0;
            }}
            button {{
                background: #173b70;
                color: white;
                border: 0;
                border-radius: 6px;
                cursor: pointer;
            }}
            .document {{
                border-bottom: 1px solid #ddd;
                padding: 12px 0;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>TrustVault Documents</h1>
            {content}
        </div>
    </body>
    </html>
    """


def valid_file_content(extension, data):
    """Check basic file signatures; this is not malware scanning."""

    if extension == ".pdf":
        return data.startswith(b"%PDF-")

    if extension == ".doc":
        return data.startswith(bytes.fromhex("D0CF11E0A1B11AE1"))

    if extension == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
                return (
                    "[Content_Types].xml" in names
                    and "word/document.xml" in names
                    and len(names) <= 2000
                    and sum(item.file_size for item in archive.infolist())
                    <= 50 * 1024 * 1024
                )
        except (zipfile.BadZipFile, OSError):
            return False

    if extension == ".txt":
        try:
            text = data.decode("utf-8-sig")
            return "\x00" not in text
        except UnicodeDecodeError:
            return False

    return False


@router.get("/documents", response_class=HTMLResponse)
async def documents_page(request: Request, search: str = ""):
    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    token = html.escape(get_csrf_token(request), quote=True)
    search_text = search.strip()

    db = get_db()

    try:
        if search_text:
            pattern = f"%{search_text}%"

            documents = db.execute(
                """
                SELECT id, filename, size, created_at
                FROM documents
                WHERE owner_id = ? AND filename LIKE ?
                ORDER BY id DESC
                """,
                (user_id, pattern)
            ).fetchall()

            shared_documents = db.execute(
                """
                SELECT d.id, d.filename, d.size, d.created_at
                FROM documents d
                JOIN grants g ON d.id = g.document_id
                WHERE g.user_id = ?
                  AND g.permission = 'read'
                  AND d.filename LIKE ?
                ORDER BY d.id DESC
                """,
                (user_id, pattern)
            ).fetchall()
        else:
            documents = db.execute(
                """
                SELECT id, filename, size, created_at
                FROM documents
                WHERE owner_id = ?
                ORDER BY id DESC
                """,
                (user_id,)
            ).fetchall()

            shared_documents = db.execute(
                """
                SELECT d.id, d.filename, d.size, d.created_at
                FROM documents d
                JOIN grants g ON d.id = g.document_id
                WHERE g.user_id = ? AND g.permission = 'read'
                ORDER BY d.id DESC
                """,
                (user_id,)
            ).fetchall()

    finally:
        db.close()

    safe_search = html.escape(search_text, quote=True)

    content = f"""
        <h2>Upload a Document</h2>

        <form action="/documents/upload"
              method="post"
              enctype="multipart/form-data">

            <input type="hidden" name="csrf_token" value="{token}">

            <input type="file"
                   name="file"
                   accept=".pdf,.doc,.docx,.txt"
                   required>

            <br>
            <button type="submit">Upload Document</button>
        </form>

        <p>Maximum file size: 10 MB.</p>

        <h2>My Documents</h2>

        <form action="/documents" method="get">
            <input type="text"
                   name="search"
                   value="{safe_search}"
                   placeholder="Search documents by filename">
            <button type="submit">Search</button>
        </form>
    """

    if documents:
        for doc in documents:
            filename = html.escape(doc["filename"])
            size = doc["size"]
            doc_id = doc["id"]

            content += f"""
                <div class="document">
                    <strong>{filename}</strong>
                    <p>Size: {size} bytes</p>

                    <a href="/documents/{doc_id}/download">Download</a>

                    <form action="/documents/{doc_id}/delete"
                          method="post"
                          onsubmit="return confirm('Delete this document?');">
                        <input type="hidden" name="csrf_token" value="{token}">
                        <button type="submit">Delete Document</button>
                    </form>

                    <h4>Share this document</h4>

                    <form action="/documents/{doc_id}/share" method="post">
                        <input type="hidden" name="csrf_token" value="{token}">
                        <input type="text" name="username"
                               placeholder="Recipient username" required>
                        <button type="submit">Grant Read Access</button>
                    </form>

                    <h4>Revoke Document Access</h4>

                    <form action="/documents/{doc_id}/revoke" method="post">
                        <input type="hidden" name="csrf_token" value="{token}">
                        <input type="text" name="username"
                               placeholder="Username to revoke" required>
                        <button type="submit">Revoke Access</button>
                    </form>
                </div>
            """
    else:
        content += "<p>No matching documents found.</p>"

    content += '<p><a href="/dashboard">Back to Dashboard</a></p>'
    content += "<h2>Shared with me</h2>"

    if shared_documents:
        for doc in shared_documents:
            filename = html.escape(doc["filename"])
            doc_id = doc["id"]
            content += f"""
                <div class="document">
                    <strong>{filename}</strong>
                    <p>Size: {doc["size"]} bytes</p>
                    <a href="/documents/{doc_id}/download">
                        Download Shared Document
                    </a>
                </div>
            """
    else:
        content += "<p>No documents have been shared with you.</p>"

    return document_page(content)


@router.post("/documents/upload")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    csrf_token: str = Form(...)
):
    verify_csrf_token(request, csrf_token)

    user_id = request.session.get("user_id")

    if not user_id:
        raise HTTPException(status_code=401, detail="Please sign in")

    original_name = Path(file.filename or "").name

    if not original_name or original_name in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid filename")

    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Only PDF, DOC, DOCX and TXT files are allowed"
        )

    data = await file.read(MAX_FILE_SIZE + 1)

    if not data:
        raise HTTPException(status_code=400, detail="Empty file")

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds 10 MB")

    if not valid_file_content(extension, data):
        raise HTTPException(
            status_code=400,
            detail="File content does not match the selected file type"
        )

    stored_name = f"{uuid.uuid4().hex}{extension}"
    file_path = PRIVATE_DIR / stored_name

    db = get_db()

    try:
        file_path.write_bytes(data)

        cursor = db.execute(
            """
            INSERT INTO documents
            (owner_id, filename, stored_name, content_type, size)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                original_name,
                stored_name,
                file.content_type,
                len(data)
            )
        )

        db.execute(
            """
            INSERT INTO audit_logs
            (actor_id, document_id, action, details)
            VALUES (?, ?, 'upload', ?)
            """,
            (user_id, cursor.lastrowid, "Document uploaded")
        )

        db.commit()

    except Exception:
        db.rollback()

        if file_path.exists():
            file_path.unlink()

        raise HTTPException(
            status_code=500,
            detail="Document upload failed"
        )

    finally:
        db.close()
        await file.close()

    return RedirectResponse("/documents", status_code=303)


@router.get("/documents/{document_id}/download")
async def download_document(document_id: int, request: Request):
    user_id = request.session.get("user_id")

    if not user_id:
        raise HTTPException(status_code=401, detail="Please sign in")

    db = get_db()

    try:
        user = db.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid account")

        document = db.execute(
            "SELECT * FROM documents WHERE id = ?", (document_id,)
        ).fetchone()

        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        grant = db.execute(
            """
            SELECT id FROM grants
            WHERE document_id = ? AND user_id = ? AND permission = 'read'
            """,
            (document_id, user_id)
        ).fetchone()

        is_owner = document["owner_id"] == user_id
        is_admin = user["role"] == "admin"

        if not (is_owner or is_admin or grant):
            db.execute(
                """
                INSERT INTO audit_logs
                (actor_id, document_id, action, details)
                VALUES (?, ?, 'denied_download', ?)
                """,
                (user_id, document_id, "Unauthorized download attempt")
            )
            db.commit()

            raise HTTPException(
                status_code=403,
                detail="You are not allowed to access this document"
            )

        file_path = (PRIVATE_DIR / document["stored_name"]).resolve()

        if file_path.parent != PRIVATE_DIR.resolve() or not file_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="Stored document not found"
            )

        db.execute(
            """
            INSERT INTO audit_logs
            (actor_id, document_id, action, details)
            VALUES (?, ?, 'download', ?)
            """,
            (user_id, document_id, "Document downloaded")
        )
        db.commit()

        filename = document["filename"]
        content_type = document["content_type"] or "application/octet-stream"

    finally:
        db.close()

    return FileResponse(
        path=file_path,
        filename=filename,
        media_type=content_type
    )


@router.post("/documents/{document_id}/share")
async def share_document(
    document_id: int,
    request: Request,
    username: str = Form(...),
    csrf_token: str = Form(...)
):
    verify_csrf_token(request, csrf_token)

    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    username = username.strip()

    if not username:
        raise HTTPException(status_code=400, detail="Recipient is required")

    db = get_db()

    try:
        user = db.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        document = db.execute(
            "SELECT owner_id FROM documents WHERE id = ?", (document_id,)
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid account")

        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        if document["owner_id"] != user_id and user["role"] != "admin":
            raise HTTPException(
                status_code=403,
                detail="Only the owner or administrator can share documents"
            )

        recipient = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")

        if recipient["id"] == user_id:
            raise HTTPException(
                status_code=400,
                detail="You cannot share a document with yourself"
            )

        db.execute(
            """
            INSERT INTO grants (document_id, user_id, permission)
            VALUES (?, ?, 'read')
            ON CONFLICT(document_id, user_id)
            DO UPDATE SET permission = 'read'
            """,
            (document_id, recipient["id"])
        )

        db.execute(
            """
            INSERT INTO audit_logs
            (actor_id, document_id, action, details)
            VALUES (?, ?, 'share', ?)
            """,
            (user_id, document_id, "Read permission granted")
        )

        db.commit()

    finally:
        db.close()

    return RedirectResponse("/documents", status_code=303)


@router.post("/documents/{document_id}/revoke")
async def revoke_access(
    document_id: int,
    request: Request,
    username: str = Form(...),
    csrf_token: str = Form(...)
):
    verify_csrf_token(request, csrf_token)

    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    username = username.strip()

    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    db = get_db()

    try:
        user = db.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        document = db.execute(
            "SELECT owner_id FROM documents WHERE id = ?", (document_id,)
        ).fetchone()

        if not user or not document:
            raise HTTPException(
                status_code=404,
                detail="Document or account not found"
            )

        if document["owner_id"] != user_id and user["role"] != "admin":
            raise HTTPException(
                status_code=403,
                detail="Only the owner or administrator can revoke access"
            )

        recipient = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")

        result = db.execute(
            "DELETE FROM grants WHERE document_id = ? AND user_id = ?",
            (document_id, recipient["id"])
        )

        if result.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="No access permission exists for this user"
            )

        db.execute(
            """
            INSERT INTO audit_logs
            (actor_id, document_id, action, details)
            VALUES (?, ?, 'revoke', ?)
            """,
            (user_id, document_id, "Read access revoked")
        )

        db.commit()

    finally:
        db.close()

    return RedirectResponse("/documents", status_code=303)


@router.post("/documents/{document_id}/delete")
async def delete_document(
    document_id: int,
    request: Request,
    csrf_token: str = Form(...)
):
    verify_csrf_token(request, csrf_token)

    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    db = get_db()

    try:
        user = db.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        document = db.execute(
            "SELECT * FROM documents WHERE id = ?", (document_id,)
        ).fetchone()

        if not user or not document:
            raise HTTPException(
                status_code=404,
                detail="Document or account not found"
            )

        if document["owner_id"] != user_id and user["role"] != "admin":
            raise HTTPException(
                status_code=403,
                detail="Only the owner or administrator can delete documents"
            )

        file_path = (PRIVATE_DIR / document["stored_name"]).resolve()

        if file_path.parent != PRIVATE_DIR.resolve():
            raise HTTPException(status_code=400, detail="Invalid document path")

        filename = document["filename"]

        db.execute(
            """
            UPDATE audit_logs
            SET details = COALESCE(details, '') || ' | Document: ' || ?,
                document_id = NULL
            WHERE document_id = ?
            """,
            (filename, document_id)
        )

        db.execute(
            """
            INSERT INTO audit_logs
            (actor_id, document_id, action, details)
            VALUES (?, NULL, 'delete', ?)
            """,
            (user_id, f"Deleted document: {filename}")
        )

        db.execute("DELETE FROM grants WHERE document_id = ?", (document_id,))
        db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        db.commit()

        # The database record and audit history are retained even if
        # physical file cleanup fails. A leftover file must be cleaned up.
        if file_path.is_file():
            try:
                file_path.unlink()
            except OSError:
                pass

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

    return RedirectResponse("/documents", status_code=303)
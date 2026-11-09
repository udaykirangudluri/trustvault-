
import os
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault(
    "TRUSTVAULT_SECRET",
    "trustvault-automated-test-secret-only"
)

# Configure an isolated database BEFORE importing the application.
import database

TEST_DIRECTORY = tempfile.TemporaryDirectory(prefix="trustvault-tests-")
TEST_ROOT = Path(TEST_DIRECTORY.name)

database.DB_PATH = TEST_ROOT / "test_trustvault.db"

from main import app
from auth import hash_password
import documents


# Keep test uploads separate from real TrustVault documents.
documents.PRIVATE_DIR = TEST_ROOT / "private"
documents.PRIVATE_DIR.mkdir(parents=True, exist_ok=True)


class TrustVaultAccessControlTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = None

    def setUp(self):
        # Clear only the isolated test database.
        db = database.get_db()

        try:
            db.execute("DELETE FROM audit_logs")
            db.execute("DELETE FROM grants")
            db.execute("DELETE FROM documents")
            db.execute("DELETE FROM login_attempts")
            db.execute("DELETE FROM users")

            db.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                """,
                ("owner_test", hash_password("OwnerPassword123!"), "owner")
            )

            db.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                """,
                ("viewer_test", hash_password("ViewerPassword123!"), "viewer")
            )

            db.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                """,
                ("admin_test", hash_password("AdminPassword123!"), "admin")
            )

            db.commit()

        finally:
            db.close()

        # Remove only files created by previous test runs.
        for path in documents.PRIVATE_DIR.iterdir():
            if path.is_file():
                path.unlink()

        from fastapi.testclient import TestClient
        self.owner = TestClient(app, base_url="https://testserver")
        self.viewer = TestClient(app, base_url="https://testserver")
        self.admin = TestClient(app, base_url="https://testserver")

    def tearDown(self):
        self.owner.close()
        self.viewer.close()
        self.admin.close()

    def get_csrf(self, client, page="/login"):
        response = client.get(page)
        self.assertEqual(response.status_code, 200)

        match = re.search(
            r'name="csrf_token"\s+value="([^"]+)"',
            response.text
        )

        self.assertIsNotNone(match, "CSRF token was not found")
        return match.group(1)

    def login(self, client, username, password):
        token = self.get_csrf(client, "/login")

        response = client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": token
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Dashboard", response.text)

    def test_private_sharing_revocation_and_audit(self):

        # 1. Log in as the document owner.
        self.login(
            self.owner,
            "owner_test",
            "OwnerPassword123!"
        )

        # 2. Upload a test document.
        token = self.get_csrf(self.owner, "/documents")

        upload_response = self.owner.post(
            "/documents/upload",
            data={"csrf_token": token},
            files={
                "file": (
                    "private-test.txt",
                    b"TrustVault private security test document",
                    "text/plain"
                )
            }
        )

        self.assertEqual(upload_response.status_code, 200)

        # Find the uploaded document in the isolated database.
        db = database.get_db()

        try:
            document = db.execute(
                """
                SELECT id FROM documents
                WHERE filename = ?
                """,
                ("private-test.txt",)
            ).fetchone()

            self.assertIsNotNone(document)
            document_id = document["id"]
        finally:
            db.close()

        # 3. Owner must be able to download their document.
        owner_download = self.owner.get(
            f"/documents/{document_id}/download"
        )

        self.assertEqual(owner_download.status_code, 200)
        self.assertEqual(
            owner_download.content,
            b"TrustVault private security test document"
        )

        # 4. An unauthenticated user must be rejected.
        anonymous = self.viewer.get(
            f"/documents/{document_id}/download"
        )

        self.assertEqual(anonymous.status_code, 401)

        # 5. Log in as a different viewer.
        self.login(
            self.viewer,
            "viewer_test",
            "ViewerPassword123!"
        )

        # 6. Viewer must not download a private document.
        denied = self.viewer.get(
            f"/documents/{document_id}/download"
        )

        self.assertEqual(denied.status_code, 403)

        # 7. Owner shares the document with the viewer.
        token = self.get_csrf(self.owner, "/documents")

        share_response = self.owner.post(
            f"/documents/{document_id}/share",
            data={
                "username": "viewer_test",
                "csrf_token": token
            }
        )

        self.assertEqual(share_response.status_code, 200)

        # 8. Viewer can download after receiving permission.
        allowed = self.viewer.get(
            f"/documents/{document_id}/download"
        )

        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(
            allowed.content,
            b"TrustVault private security test document"
        )

        # 9. Owner revokes the viewer's permission.
        token = self.get_csrf(self.owner, "/documents")

        revoke_response = self.owner.post(
            f"/documents/{document_id}/revoke",
            data={
                "username": "viewer_test",
                "csrf_token": token
            }
        )

        self.assertEqual(revoke_response.status_code, 200)

        # 10. Viewer must immediately lose download access.
        revoked_download = self.viewer.get(
            f"/documents/{document_id}/download"
        )

        self.assertEqual(revoked_download.status_code, 403)

        # 11. Viewer cannot access administrator audit logs.
        viewer_audit = self.viewer.get("/audit")

        self.assertEqual(viewer_audit.status_code, 403)

        # 12. Administrator can access audit logs.
        self.login(
            self.admin,
            "admin_test",
            "AdminPassword123!"
        )

        admin_audit = self.admin.get("/audit")

        self.assertEqual(admin_audit.status_code, 200)
        self.assertIn("TrustVault Audit Logs", admin_audit.text)

        # 13. Confirm denied-download activity was recorded.
        self.assertIn("denied_download", admin_audit.text)
        self.assertIn("private-test.txt", admin_audit.text)


if __name__ == "__main__":
    unittest.main()

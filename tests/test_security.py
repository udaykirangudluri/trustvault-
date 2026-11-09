
import os
import unittest

# A test-only secret. Never use this value for deployment.
os.environ.setdefault(
    "TRUSTVAULT_SECRET",
    "trustvault-automated-test-secret-only"
)

from fastapi.testclient import TestClient
from main import app


class TrustVaultSecurityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # HTTPS is used because TrustVault cookies require HTTPS.
        cls.client = TestClient(app, base_url="https://testserver")

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

    def test_registration_page_opens(self):
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn("csrf_token", response.text)

    def test_login_page_opens(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("csrf_token", response.text)

    def test_login_rejects_invalid_csrf_token(self):
        response = self.client.post(
            "/login",
            data={
                "username": "testuser",
                "password": "incorrect-password",
                "csrf_token": "invalid-token"
            }
        )
        self.assertEqual(response.status_code, 403)

    def test_registration_rejects_invalid_csrf_token(self):
        response = self.client.post(
            "/register",
            data={
                "username": "testuser",
                "password": "test-password-123",
                "csrf_token": "invalid-token"
            }
        )
        self.assertEqual(response.status_code, 403)

    def test_login_rejects_missing_csrf_token(self):
        response = self.client.post(
            "/login",
            data={
                "username": "testuser",
                "password": "incorrect-password"
            }
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()

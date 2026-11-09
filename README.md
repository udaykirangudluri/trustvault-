# TrustVault - Secure Document Management System

## 1. Project Overview

TrustVault is a Python-based Document Management System designed to help users store, organize, search, share and access confidential documents.

The main security objective is:

**The wrong person must not be able to access a document, and the system should record who accessed it and when.**

## 2. Technologies Used

- Python
- FastAPI
- SQLite
- HTML
- Starlette session middleware
- PBKDF2-HMAC-SHA256 password hashing

## 3. Main Features

- User registration and login
- Role-based access control
- Document upload and storage
- Document search
- Per-document read permissions
- Document sharing and access revocation
- Document deletion
- Audit logging
- CSRF protection for form submissions
- Basic file type and size validation
- Login attempt limiting

## 4. User Roles

| Role | Permissions |
|---|---|
| Administrator | Administrative access, including audit records and document management |
| Owner | Access and management of documents they own |
| Viewer | Access to documents explicitly shared with them |

Newly registered users receive the viewer role by default.

Document ownership is also tracked separately for each document.

## 5. Project Structure

```text
trustvault-/
├── main.py
├── database.py
├── auth.py
├── security.py
├── documents.py
├── audit.py
├── requirements.txt
├── trustvault.db
├── storage/
│   └── private/
├── tests/
│   └── test_security.py
├── README.md
├── THREATS.md
└── PROMPTS.md
```

## 6. Installation

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Generate a session secret and start the application:

```bash
export TRUSTVAULT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Keep the secret private. Store a persistent secret securely for deployment.

## 7. Accessing the Application

Open the forwarded HTTPS port 8000 URL provided by GitHub Codespaces.

Useful routes:

- `/` - Home
- `/register` - Registration
- `/login` - Login
- `/dashboard` - Dashboard
- `/documents` - Document management
- `/audit` - Audit records
- `/health` - Health check

## 8. Running Automated Tests

Run:

```bash
python -m unittest discover -s tests -v
```

The initial security test suite checks the health endpoint, registration and login pages, and CSRF rejection behavior.

## 9. Important Security Limitations

This is an academic project and is not yet production-ready.

- Uploaded files are not scanned for malware.
- Audit records are not tamper-proof against someone with database access.
- The database and uploaded files need reliable backups.
- Encryption at rest has not been implemented.
- Login limiting is based on usernames and may allow account-lockout abuse.
- Security headers, deployment hardening and monitoring need further work.
- The current test suite does not prove every security property.

Before handling real confidential documents, the system needs an independent security review and additional protections.

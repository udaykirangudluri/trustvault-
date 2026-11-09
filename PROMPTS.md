# TrustVault - AI Usage Record

## 1. Purpose

AI assistance was used during the development of TrustVault to understand the requirements, plan the application, write and review code, troubleshoot errors and prepare documentation.

The developer remains responsible for testing and verifying the application.

## 2. Examples of Prompts Used

The following are representative prompts based on the development process. They are paraphrased examples, not a verbatim transcript.

### Project planning
"Help me create a Python-based Document Management System called TrustVault, with authentication, document permissions and audit logging."

### Beginner guidance
"Guide me step by step with the exact files and code because I am a beginner."

### Troubleshooting
"Help me understand and fix the errors appearing in my terminal and browser."

### Access control
"Help me implement document sharing, revocation and checks that prevent unauthorized downloads."

### Security improvements
"Help me add CSRF protection, password hashing, login attempt limiting and file validation."

### Testing
"Help me create automated security tests for the TrustVault application."

### Documentation
"Help me prepare README.md, THREATS.md and PROMPTS.md for the project."

## 3. Developer Verification and Corrections

AI-generated code was not accepted as correct without checking it.

Examples of verification performed:

1. Checked Python files using `python -m py_compile`.
2. Initialized and checked the SQLite database.
3. Started the FastAPI server and checked the application in a browser.
4. Tested document upload, search, download, sharing and revocation.
5. Checked that revoked users could no longer download a shared document.
6. Ran the automated security test suite.
7. Observed a deprecation warning concerning the installed HTTPX and Starlette test client integration, even though all six tests passed.

## 4. Automated Test Evidence

Command used:

```bash
python -m unittest discover -s tests -v
```

Recorded result:

- Tests run: 7
- Passed: 7
- Failed: 0
- Result: OK

## 5. Limitations of AI Assistance

AI-generated code may contain errors, incomplete security controls or assumptions about the development environment.

The application was tested during development, but the initial tests do not cover every threat. Additional testing and independent security review are necessary before real confidential documents are stored.

## 6. Developer Responsibility

The developer is responsible for understanding the implementation, verifying the behavior, correcting errors and explaining the security limitations during the project demonstration.

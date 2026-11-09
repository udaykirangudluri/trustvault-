# TrustVault Threat Model

## 1. Security Objective

Prevent unauthorized users from accessing confidential documents and maintain records of document access and security-related actions.

## 2. Assets to Protect

- User accounts and password hashes
- Uploaded confidential documents
- Document ownership information
- Document sharing permissions
- Session information
- Audit records

## 3. Threats and Controls

| ID | Threat | Current protection | Verification |
|---|---|---|---|
| T01 | Unauthorized user downloads another user's document | Ownership, administrator and read-grant checks | Manual direct-download and permission tests |
| T02 | User retains access after sharing permission is revoked | Revoke operation removes the grant | Manual revocation test |
| T03 | Attacker submits a forged form request | CSRF token verification | Automated invalid-token tests |
| T04 | Attacker submits a form without a CSRF token | Required form token and verification | Automated missing-token test |
| T05 | Password database is exposed | PBKDF2-HMAC-SHA256 with a random salt | Code inspection |
| T06 | Repeated incorrect login attempts | Temporary username-based login lockout | Further automated testing required |
| T07 | Malicious filename or HTML content causes script injection | HTML escaping of displayed user-controlled values | Code inspection and further testing required |
| T08 | Invalid or oversized files are uploaded | Extension, size and basic file-format validation | Manual upload tests |
| T09 | Private files are accessed through a public static directory | Files are stored in a private storage directory and served through an authorized route | Manual access test |
| T10 | User actions cannot be investigated | Audit records capture document-related actions | Manual audit-page test |

## 4. Additional Threats and Limitations

### Session theft
A stolen session cookie may allow an attacker to act as the user. HTTPS and secure cookie settings help protect the session in transit, but additional session management and monitoring are needed.

### Administrator compromise
An attacker with administrator or server access may access documents and modify database records. Strong administrative account protection and infrastructure security are required.

### Account lockout abuse
The current login lockout is based on usernames. An attacker may deliberately cause another user's account to be temporarily locked.

### Malware uploads
Basic file validation does not detect malware. A malware scanning service is required before accepting real confidential files.

### Database and audit tampering
Someone with direct database access may modify or delete audit records. Tamper-evident or externally stored audit records are needed for stronger accountability.

### Data loss
The current project needs a tested backup and recovery process for its SQLite database and private document files.

## 5. Testing Evidence

The initial automated suite is:

```bash
python -m unittest discover -s tests -v
```

Current result: seven tests passed, including an end-to-end access-control test.

The tests cover:
- Health endpoint response
- Registration page response
- Login page response
- Invalid CSRF token rejection on login
- Missing CSRF token rejection on login
- Invalid CSRF token rejection on registration
- Owner and viewer download authorization
- Sharing and immediate revocation
- Administrator-only audit access
- Audit recording of denied downloads

Manual checks have also been performed for document search, sharing, revocation, downloading and deletion.

These checks provide initial evidence, not a guarantee that every possible attack is prevented.

## 6. Future Security Improvements

1. Add automated tests for cross-user document access.
2. Add automated tests for sharing and revocation.
3. Add IP-aware rate limiting using trusted proxy configuration.
4. Add malware scanning.
5. Add encryption at rest and secure backups.
6. Add security headers and a Content Security Policy.
7. Add stronger audit integrity protection.
8. Perform independent security testing before production use.

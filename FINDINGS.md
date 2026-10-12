# Vulnerability Findings — <Shekinah D. Bolante> & <Louezethe N. Saldua>

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | A03:2025-Injection | `/login` / lines 113-122 | Attackers can inject SQL through the username field and bypass authentication or dump user data. | Use a parameterized query instead of f-string SQL: `SELECT id, password FROM users WHERE username = ?`. |
| 2 | A01:2025-Broken Access Control | `/notes/{note_id}` / lines 132-138 | Anyone who knows another user's note ID can read private notes without verifying ownership. | Check that `row["owner_id"] == user["id"]` before returning the note. |
| 3 | A01:2025-Broken Access Control | `/admin/users` / lines 152-161 | The broad `except Exception: pass` lets non-admin users continue to the admin list and view all accounts. | Fail closed and raise `HTTPException(403, "Admins only")` before querying users. |
| 4 | A07:2025-Identification and Authentication Failures | `/register` + `/login` / lines 45-68 and 113-122 | Passwords are stored and checked in plaintext, so a database breach exposes every account immediately. | Hash passwords with `hashlib.pbkdf2_hmac` and compare only the derived hash. |
| 5 | A02:2025-Cryptographic Failures | lines 28-29 | A hardcoded secret is exposed in source code, making JWT-like or signing logic easy to forge or reverse. | Load the secret from a secure environment variable instead of embedding it in the code. |
| 6 | A05:2025-Security Misconfiguration | lines 31-37 and 93-99 | Overly permissive CORS and verbose traceback responses expose internal API details and widen attack surface. | Restrict `allow_origins` to trusted domains and return sanitized error messages without stack traces. |

## Reflection (3–4 sentences)
The most damaging bug is the broken access control in the note lookup because it exposes private data directly and can be abused by anyone who guesses or discovers a valid note ID. This type of issue often causes the largest real-world impact because it violates confidentiality without having to crack credentials. It is especially serious because the bug requires no special privileges and can be exploited repeatedly at scale.

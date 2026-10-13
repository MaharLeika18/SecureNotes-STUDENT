# Vulnerability Findings

| # | OWASP 2025 code & name | Where | Attack | 1-line fix |
|---|---|---|---|---|
| 1 | A03:2025-Injection | `/login` | SQL injection through username | Use a parameterized query instead of string interpolation. |
| 2 | A01:2025-Broken Access Control | `/notes/{note_id}` | Anyone can fetch another user’s private note by ID | Check `row["owner_id"] == user["id"]` before returning it. |
| 3 | A01:2025-Broken Access Control | `/admin/users` | Non-admin users can bypass the admin check | Fail closed with `HTTPException(403, "Admins only")`. |
| 4 | A07:2025-Identification and Authentication Failures | `/register` + `/login` | Passwords are stored and compared in plaintext | Hash passwords before storing and comparing them. |
| 5 | A02:2025-Cryptographic Failures | app config | Hardcoded secret exposed in source code | Load the secret from an environment variable. |
| 6 | A05:2025-Security Misconfiguration | CORS + exception handler | Overly permissive CORS and traceback leaks internal details | Restrict origins and return a safe generic error. |

## Reflection
The most damaging issue is the note access bug because it exposes private data without needing credentials or admin access. It violates confidentiality directly and can affect many users if note IDs are guessed or discovered. In a real app, this would lead to privacy leaks and serious trust issues.

# Vulnerability Findings — Louezethe & Shekinah

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | A01 - Broken Access Control | GET /notes/{notes_id} | Can view another user's records by id | Include owner_id in the WHERE condition |
| 2 | A02 - Security Misconfiguration | Code block 31, Line 29, Code block 94 | Any website on the internet may read the API responses, users can access exposed secrets and exploit the internal file paths revealed in stack trace errors | Include only the localhost route in allowed origins, store the secret in .env, use FastAPI's error handling per route instead of a generic error handler |
| 3 | A04 - Cryptographic Failures | Code block 45, POST /register, POST /login | Exposed sensitive data can be used for unauthorized access | Sensitive data should be hashed with a secret salt |
| 4 | A05 - Injection | POST /login | SQL queries can be injected to obtain and delete data | Use a parameter |
| 5 | A07 - Authentication Failures | function current_user, POST /login | Anyone can send the guessable token and become admin | Use signed, expiring tokens |
| 6 | A10 - Exceptional Conditions | GET /admin/users | Everyone can see all registered users | Remove the try-except block |

## Reflection (3–4 sentences)
Which bug would do the most damage in a real app, and why?
The A05 Injection bug would do the most damage in a real app because it leaves bad actors access to the database itself. This means that they could modify the SQL query to read all records and leak sensitive data from the current table or even all tables. They might invoke stored protocols to insert and poison the database records. Worse, they could modify and even delete the stored records leading to potentially permanent damage especially if backups fail.
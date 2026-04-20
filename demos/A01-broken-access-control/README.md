# OWASP A01:2021 – Broken Access Control

## What Is It?

Broken Access Control happens when an application does not enforce that users can only act on resources they own or are permitted to access. The most common form is an **Insecure Direct Object Reference (IDOR)**: a user changes an ID in a URL or request body and receives data belonging to another user.

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/app.py` | Flask API — any user can read any other user's record (including SSN) by changing the `user_id` in the URL |
| `fixed/app.py` | Flask API — ownership enforced via a signed JWT; sensitive fields stripped from the response |

## How to Run

### Prerequisites

```bash
pip install flask pyjwt
```

### Vulnerable Version

```bash
cd vulnerable
python app.py
```

**Exploit — access another user's data:**

```bash
# Pretend to be user 1 by setting the forged header, then request user 2's record
curl -H "X-User-Id: 1" http://127.0.0.1:5000/user/2
# Returns bob's SSN — data that alice should never see
```

### Fixed Version

```bash
cd fixed
python app.py
```

**Generate a test JWT (run once in Python):**

```python
import jwt
token = jwt.encode({"user_id": 1}, "change-me-in-production", algorithm="HS256")
print(token)
```

**Authorised request — own record:**

```bash
curl -H "Authorization: Bearer <token>" http://127.0.0.1:5000/user/1
# Returns alice's non-sensitive fields only
```

**Forbidden request — another user's record:**

```bash
curl -H "Authorization: Bearer <token_for_user_1>" http://127.0.0.1:5000/user/2
# Returns 403 Forbidden
```

## Key Fixes

1. **Server-side identity verification** — a signed JWT replaces the forgeable `X-User-Id` header.
2. **Ownership check** — the server compares the token's `user_id` claim against the requested resource ID.
3. **Field-level access control** — the response excludes sensitive fields (SSN) even for the resource owner.
4. **`debug=False`** — removes the interactive Werkzeug debugger from production.

## References

- [OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP IDOR Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)

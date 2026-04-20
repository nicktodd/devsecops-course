# OWASP A03:2021 – Injection

## What Is It?

Injection occurs when untrusted data is sent to an interpreter (SQL engine, OS shell, LDAP server, etc.) as part of a command or query. The interpreter cannot distinguish between the intended command structure and the injected data, so it executes attacker-supplied code.

SQL Injection (SQLi) is the most prevalent form and can lead to:
- Authentication bypass
- Extraction of the entire database contents
- Modification or destruction of data

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/app.py` | Flask login endpoint that concatenates user input directly into a SQL string |
| `fixed/app.py` | Same endpoint using parameterised queries — injection is impossible |

## How to Run

### Prerequisites

```bash
pip install flask
```

### Vulnerable Version

```bash
cd vulnerable
python app.py
```

**Legitimate login:**

```bash
curl "http://127.0.0.1:5000/login?username=alice&password=secret"
# {"logged_in": true, "role": "user"}
```

**Bypass authentication (inject always-true condition):**

```bash
curl "http://127.0.0.1:5000/login?username=%27+OR+%271%27%3D%271%27+--&password=x"
# Decoded username: ' OR '1'='1' --
# Returns: {"logged_in": true, "role": "admin"}  <-- logged in as admin with no valid password
```

**What the injected SQL looks like:**

```sql
-- Intended query:
SELECT * FROM users WHERE username='alice' AND password='secret'

-- Injected query (username = ' OR '1'='1' --):
SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='x'
--                                       ^^^^^^^^^  always true
--                                                  ^^ rest of query commented out
```

### Fixed Version

```bash
cd fixed
python app.py
```

**Same injection attempt — now returns 401:**

```bash
curl "http://127.0.0.1:5000/login?username=%27+OR+%271%27%3D%271%27+--&password=x"
# {"logged_in": false}
```

The injected string is passed to the database driver as a literal value. The database looks for a user whose username is literally `' OR '1'='1' --` — which does not exist.

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Query construction | String concatenation with f-string | Parameterised query with `?` placeholders |
| Input handling | User input embedded in SQL | User input passed as a separate data tuple |
| Error messages | Raw `sqlite3` errors returned to client | Generic "Database error" message |
| Debug mode | `debug=True` | `debug=False` |

## References

- [OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

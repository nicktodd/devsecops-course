# OWASP A09:2021 – Security Logging and Monitoring Failures

## What Is It?

Security Logging and Monitoring Failures occur when an application does not produce adequate audit logs, or produces logs that contain sensitive data, or swallows errors silently. Without proper logging:

- Attacks (brute-force, credential stuffing, data exfiltration) go undetected
- Incident response teams have no evidence to investigate a breach
- Sensitive data in logs becomes a secondary attack surface

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/app.py` | Logs passwords and API keys in plaintext; swallows exceptions silently; no failed-login logging |
| `fixed/app.py` | Masks sensitive values before logging; proper error logging with `exc_info=True`; WARNING log on every failed authentication |

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

**Trigger a login and observe the log output:**

```bash
curl -s -X POST http://127.0.0.1:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"secret"}'
```

**Console output (note the plaintext password and token):**

```
DEBUG Login attempt: username=alice, password=secret
INFO  Login successful for alice. Token: tok_abc123xyz
```

**Make a failed login — observe that nothing is logged:**

```bash
curl -s -X POST http://127.0.0.1:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"wrong"}'
```

No log line is produced — a brute-force attack is completely invisible.

### Fixed Version

```bash
cd fixed
python app.py
```

**Successful login — password is never logged:**

```bash
curl -s -X POST http://127.0.0.1:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"secret"}'
```

```
INFO  Login attempt | user=alice | ip=127.0.0.1
INFO  Login successful | user=alice | ip=127.0.0.1
```

**Failed login — WARNING is generated for alerting:**

```bash
curl -s -X POST http://127.0.0.1:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"wrong"}'
```

```
INFO    Login attempt | user=alice | ip=127.0.0.1
WARNING Failed login | user=alice | ip=127.0.0.1
```

In production, a SIEM or CloudWatch alarm would fire if the WARNING rate exceeds a threshold (e.g., 10 failures per minute from the same IP).

**Transfer with API key — key is masked:**

```bash
curl -s -X POST http://127.0.0.1:5000/transfer \
     -H "Content-Type: application/json" \
     -H "X-API-Key: sk_live_abc123xyz" \
     -d '{"amount":100,"to_account":"ACC-999"}'
```

```
INFO Transfer initiated | amount=100 | to=ACC-999 | key_prefix=sk_l***
```

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Password in logs | Logged in plaintext | Never logged |
| Session token in logs | Logged in plaintext | Never logged |
| API key in logs | Full value logged | Only first 4 chars + `***` |
| Failed login event | No log entry | `WARNING` with username and IP |
| Exception handling | Silent `pass` — error hidden | `logger.error(..., exc_info=True)` — full traceback |
| HTTP status on error | `200 OK` even after exception | `500 Internal Server Error` |
| Log level | `DEBUG` (too verbose) | `INFO` in production |

## References

- [OWASP A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)

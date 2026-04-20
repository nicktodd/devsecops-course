# OWASP A04:2021 – Insecure Design

## What Is It?

Insecure Design covers flaws that exist at the **architecture and design** level — not just implementation bugs. Even perfectly written code can be insecure if the underlying design failed to account for security requirements.

This demo shows a password reset flow with multiple design flaws that make it trivially brute-forceable, regardless of how cleanly the code itself is written.

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/app.py` | Password reset with a 4-digit OTP, no rate limiting, no expiry, no attempt limit |
| `vulnerable/brute_force.py` | Script that cracks the OTP by trying all 10,000 possibilities |
| `fixed/app.py` | Redesigned flow: 6-digit CSPRNG OTP, 5-minute expiry, 5-attempt lockout, constant-time comparison |

## How to Run

### Prerequisites

```bash
pip install flask requests
```

### Vulnerable Version — Watch It Get Cracked

**Terminal 1 — start the server:**

```bash
cd vulnerable
python app.py
```

**Terminal 2 — run the brute-force:**

```bash
python brute_force.py
```

You will see the brute-force script find the correct OTP within seconds. The server logs will show the actual OTP value in the `[DEBUG]` line — confirming it matches what the script found.

### Fixed Version — Brute-Force Is Blocked

```bash
cd fixed
python app.py
```

**Request an OTP:**

```bash
curl -s -X POST http://127.0.0.1:5000/request-reset \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com"}'
```

**After 5 incorrect guesses, the OTP is destroyed:**

```bash
for i in 1 2 3 4 5 6; do
  curl -s -X POST http://127.0.0.1:5000/verify-otp \
       -H "Content-Type: application/json" \
       -d '{"email":"test@example.com","otp":"0000"}'
  echo
done
# Attempt 6 returns: 429 Too Many Requests
```

## Design Flaws Fixed

| Flaw | Vulnerable | Fixed |
|---|---|---|
| OTP keyspace | 4 digits = 10,000 values | 6 digits = 1,000,000 values |
| Random source | `random.randint` (not cryptographically secure) | `secrets.randbelow` (CSPRNG) |
| OTP expiry | None — valid forever | 5 minutes |
| Attempt limit | None — unlimited guesses | 5 attempts then OTP destroyed |
| Comparison | `==` operator (may leak timing info) | `secrets.compare_digest` (constant-time) |
| Failed attempt logging | Silent | Logged with attempt count |

## References

- [OWASP A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

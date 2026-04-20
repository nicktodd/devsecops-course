# OWASP A07:2021 – Identification and Authentication Failures

## What Is It?

Authentication failures occur when an application's identity and session management controls are implemented incorrectly. Attackers exploit these weaknesses to impersonate legitimate users. Common patterns include:

- **Predictable session tokens** — tokens generated with a non-cryptographic PRNG can be guessed or reconstructed
- **No account lockout** — unlimited failed login attempts enable brute-force and credential stuffing attacks
- **Weak or default credentials** — accounts like `admin/admin` are the first thing attackers try

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/AuthService.java` | `java.util.Random` tokens, no lockout, weak default credential, no session expiry |
| `fixed/AuthService.java` | `SecureRandom` 256-bit tokens, account lockout after 5 failures, 30-minute session TTL |

## How to Run

### Prerequisites

- Java 11+

### Vulnerable Version

```bash
cd vulnerable
javac AuthService.java
java AuthService
```

**Observe:**
- Tokens are short (up to 6 digits) and generated sequentially — run twice and compare outputs
- `admin/admin` authenticates successfully
- Calling `login("alice", "wrongpassword")` can be called indefinitely with no lockout

### Fixed Version

```bash
cd fixed
javac AuthService.java
java AuthService
```

**Observe:**
- Tokens are 43-character Base64 strings with 256-bit entropy — no pattern, unpredictable
- After 5 failed attempts, the account is locked and even the correct password is rejected
- A `[SECURITY]` log line is emitted for every failed attempt

**Expected output:**

```
Token 1: xK9mP2...  (43 random chars)
Token 2: aQ7nR5...  (completely different)
Attempt 1 result: REJECTED
Attempt 2 result: REJECTED
...
Attempt 5 result: REJECTED
[SECURITY] Account locked: alice — too many failed attempts (5)
Correct password after lockout: REJECTED (locked)
```

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Token PRNG | `java.util.Random` (LCG, predictable) | `SecureRandom` (OS entropy, CSPRNG) |
| Token length | 6 decimal digits (1M values) | 32 bytes Base64 (256-bit entropy) |
| Account lockout | None | Locked after 5 consecutive failures |
| Session expiry | None — tokens valid forever | 30-minute TTL enforced on validation |
| Default credentials | `admin/admin` present in code | No pre-populated credentials |
| Failed attempt logging | Silent | `[SECURITY]` log with counter |

## References

- [OWASP A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

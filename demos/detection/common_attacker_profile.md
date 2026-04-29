# Common Attacker Profile — Detection Engineering Demos

The same fictional attacker appears across all four detection engineering demos.
This allows you to trace a single threat actor's behaviour from first contact through
to exfiltration — across authentication logs, application logs, and CI/CD logs.

---

## Attacker Identity

| Field | Value |
|-------|-------|
| **User ID** | `u-4892` |
| **Username** | `k.petrov@external-contractor.io` |
| **Cognito Group** | `analyst` (read-only) |
| **Source IP** | `185.220.101.47` (Tor exit node) |
| **User-Agent** | `python-requests/2.31.0` |
| **Target system** | ESA Mission Registry API |
| **Attack date** | 2026-04-14 (UTC) |

---

## Attack Timeline

| Time (UTC) | Phase | Event |
|------------|-------|-------|
| 01:47 | Reconnaissance | Automated credential stuffing begins against `/auth/token` |
| 02:03 | Initial Access | Successful login after 14 failed attempts |
| 02:04 | Execution | JWT token issued (`exp` = 02:04 + 1h) |
| 02:05 | Discovery | `GET /missions` — enumerating all missions |
| 02:08 | Discovery | `GET /satellites` — enumerating all satellites |
| 02:11 | Discovery | `GET /launches` — enumerating all launches |
| 02:14 | Privilege Escalation | `POST /missions` — analyst attempting to create a mission (403) |
| 02:15 | Collection | `GET /missions?limit=1000` — bulk data harvest attempt |
| 02:17 | Exfiltration | 847 mission records returned in single response |
| 02:19 | Impact | Pipeline definition modified in GitHub (separate session) |
| 02:31 | Lateral Movement | New secret added to CodeBuild environment |
| 02:44 | Persistence | Malicious build runs outside scheduled hours |

---

## Notes for Instructors

- The attacker is an **insider threat** — a real contractor account that was compromised
  externally.
- The credential stuffing in Demo 1/2 would have been blocked by the Cognito
  `PreAuthentication` Lambda trigger — but that control was identified as a gap in the
  STRIDE analysis (`T-05`, `T-21`).
- The bulk harvest in Demo 2 succeeded because there was no per-user rate limit on
  `GET /missions` — another gap (`T-24`).
- The CI/CD activity in Demo 3 uses a **separate GitHub session** from a second IP
  (`91.108.4.212`) — suggesting shared or stolen credentials, not the same browser session.
- Demo 4 shows the same authentication events viewed through debug logs — demonstrating
  that the volume of log data did not help the investigation.

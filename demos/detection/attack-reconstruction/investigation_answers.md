# Demo 2 — Investigation Answers

> **Instructor copy — do not distribute to students before the exercise.**

---

## Q1 — Initial Access

**Method:** Credential stuffing — automated password guessing against the Cognito login endpoint.

**Evidence:**
- 14 consecutive `auth.login.failure` events for `k.petrov@external-contractor.io`
- All from the same `source_ip`: `185.220.101.47`
- All from the same `user_agent`: `python-requests/2.31.0` (a scripted HTTP client, not a browser)
- `attempt_number` field increments 1–14 confirming sequential automated attempts
- Followed immediately by `auth.login.success` on attempt 15

**Duration:** 01:47:03 → 02:03:11 = **16 minutes 8 seconds** from first failure to success.

**Gap to highlight:** The `PreAuthentication` Lambda trigger (Cognito account lockout) identified
as missing in the STRIDE analysis (`T-05`) would have blocked this after 5 attempts.

---

## Q2 — What Did They Access?

| Order | Time | Resource | Records Returned |
|-------|------|----------|-----------------|
| 1 | 02:05:04 | `GET /missions` | 847 |
| 2 | 02:08:19 | `GET /satellites` | 312 |
| 3 | 02:11:33 | `GET /launches` | 204 |

**Total records accessed: 1,363** across all three collections.

**Pattern:** Systematic enumeration of every collection in the API — consistent with
reconnaissance or bulk data harvest, not normal browsing behaviour.

---

## Q3 — What Did They Try and Fail At?

**Event:** `api.authorization.failure` at 02:14:02

`POST /missions` — the attacker attempted to **create a mission record**.

- Required role: `admin`
- Actual role: `analyst`
- Result: `403 Forbidden`

**What this tells us:** The attacker had already read everything available to their role
and was attempting to escalate their impact by writing data. The RBAC control in the Lambda
handler blocked this (`C-13` in the STRIDE mitigations document).

---

## Q4 — The Smoking Gun

**Line:** `req-0020` — `api.request.anomaly` at 02:15:48

```json
"path": "/missions",
"query_params": {"limit": "1000"},
"records_returned": 847,
"anomaly": "unusually_large_response"
```

**The giveaway field:** `"limit": "1000"` — the attacker explicitly requested the maximum
possible page size to harvest as many records as possible in a single request.

Combined with the `anomaly: unusually_large_response` flag, this is a clear indicator of
bulk data collection.

**Note for instructors:** Point out that this anomaly flag only exists because the application
was designed to detect and log it. Without that intentional logging decision, `req-0020`
would look identical to `req-0016`.

---

## Q5 — Attribution

**Supporting evidence:**
- Same `user_id: u-4892` on all authenticated events
- Same `source_ip: 185.220.101.47` on all 21 events
- Same `user_agent: python-requests/2.31.0` on all events
- Sequential `request_id` values (`req-0001` → `req-0020`) with no gaps
- `auth.token.issued` links `req-0015` to all subsequent requests via `user_id`

**What could undermine it:**
- The source IP is a **Tor exit node** — multiple different people could share it
- `user_id` proves the *account* was used, not the specific human — the account may have
  been compromised
- `user_agent` is trivially spoofed — it only tells us the tooling used, not the person

**Key teaching point:** Logs prove what *happened*, not always *who* caused it. Attribution
to a human requires corroboration — e.g. MFA device logs, browser fingerprinting, or a
confession. Here we can say with confidence: *the account `u-4892` was used from a Tor
exit node via an automated script to exfiltrate 1,363 records.* Whether that was Petrov
himself or someone using his stolen credentials requires further investigation.

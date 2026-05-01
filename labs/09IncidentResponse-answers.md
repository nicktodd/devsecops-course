# Lab 09 – Incident Response: Instructor Answer Key

> This file contains model answers and teaching notes for `09IncidentResponse.md`.
> Do not distribute to students before the lab is complete.

---

## Part 1C – Confirmed Facts vs Assumptions

**Confirmed facts** (directly in the logs):

- `k.petrov@external-contractor.io` made 14 failed login attempts between 01:47 and 01:55 UTC (`attack_sequence.jsonl`, req-0001–req-0014)
- Login succeeded on attempt 15 at 02:03:11 UTC from IP `185.220.101.47`
- The account holds `analyst` group membership (read-only)
- `k.petrov` modified `buildspec.yml` on `main` at 02:19:04 UTC
- `k.petrov` added the `EXFIL_ENDPOINT` environment variable to CodeBuild at 02:31:17 UTC
- Pipeline `build-2042` was triggered at 02:44:03 UTC — flagged `outside_business_hours`
- An outbound connection to `198.51.100.42:443` transmitted 2,841 bytes during the BUILD phase
- Deployment to `esa-mission-registry` completed at 02:45:47 UTC

**Unconfirmed assumptions**:

- `k.petrov` is the attacker (their account may have been compromised by a third party)
- The outbound connection successfully exfiltrated secrets (bytes sent ≠ successful receipt)
- The deployed artifact contains malicious code (size increase is suspicious but not proof)
- Any other accounts were involved

---

## Part 2 – Immediate Containment

**Take immediately** (reversible, evidence-safe):
- Pause pipelines ✅
- Block artifact promotion ✅
- Snapshot runner state ✅

**Take carefully (order matters)**:
- Disable `k.petrov` account — do *after* identifying all their activity, not before

**Defer**:
- Isolate runners — only after filesystem snapshot is complete

**Do not take yet**:
- Rotating all secrets at once (breaks dependent systems, makes it harder to verify what was actually compromised)

---

## Part 3A – Most Valuable Missing Log

Teaching note: **The content of the outbound `curl` request** is the best answer.
The artifact size anomaly and the `EXFIL_ENDPOINT` variable strongly suggest data
was sent — but without the request body, you cannot confirm *what* was sent
(build environment variables, secrets, source code). This determines the full
scope of the breach and is irretrievably lost.

Runner filesystem memory is also acceptable — it would show what was running in
the process at build time.

---

## Part 4A – Proposed Actions Tabletop

| # | Action | Decision | Approver | Reversible? |
|---|--------|----------|----------|-------------|
| 1 | Pause `esa-mission-registry` pipeline | **Take now** | On-call lead | ✅ Yes |
| 2 | Delete `build-2042` logs | **Do not take** | N/A — never | ❌ No — destroys evidence |
| 3 | Disable `k.petrov` accounts | **Take now** (after snapshot) | Security or on-call lead | ✅ Yes (re-enable if needed) |
| 4 | Rotate all secrets simultaneously | **Defer** — rotate in order | Security lead | ⚠️ Partially |
| 5 | Snapshot runner filesystem | **Take now — first action** | On-call lead | ✅ Yes |
| 6 | Force-push revert to `main` | **Defer** — after evidence collected | Engineering lead | ❌ Rewrites history |

**Teaching note on action 2**: Deleting logs is almost always the most tempting
action under pressure ("stop the leak") and almost always the worst. It destroys
evidence, may be illegal depending on jurisdiction, and doesn't actually stop
attacker access.

---

## Part 5A – Secret Rotation Order

Recommended order (reasoning: stop active access first, then rebuild trust):

1. **Artifact publishing credentials** — actively used in `build-2042`, highest confirmed exposure
2. **Code signing keys** — if the artifact was signed with a compromised key, all signed artifacts are suspect
3. **Cloud roles / deployment service accounts** — used by the pipeline; scope must be confirmed first
4. **Application secrets** — rotate after deployment targets are verified clean
5. **Everything else** — once blast radius is understood

**Why order matters**: Rotating a deployment service account before confirming all
dependent pipelines causes outages. Rotating application secrets before knowing
which services consume them causes cascading failures. Uncoordinated rotation is
how a security incident becomes a production incident.

---

## Part 7A – Timeline

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-04-14T01:47:03Z | First authentication failure from `185.220.101.47` |
| 2026-04-14T02:03:11Z | Successful login by `k.petrov` (attempt 15) |
| 2026-04-14T02:05:04Z–02:11:33Z | Full dataset bulk-downloaded from `/missions`, `/satellites`, `/launches` |
| 2026-04-14T02:19:04Z | `buildspec.yml` modified on `main` |
| 2026-04-14T02:31:17Z | `EXFIL_ENDPOINT` environment variable added to CodeBuild |
| 2026-04-14T02:44:03Z | Pipeline `build-2042` triggered |
| 2026-04-14T02:44:51Z | SAST gate breached but build continued |
| 2026-04-14T02:44:52Z | Outbound connection to `198.51.100.42` during BUILD phase |
| 2026-04-14T02:45:47Z | Deployment to `esa-mission-registry` stack completed |

### Part 7B – Gap analysis answers

- **Elapsed time**: 01:47:03 → 02:45:47 = **58 minutes 44 seconds** from first
  failed login to successful deployment
- **Earliest opportunity to detect and stop**: The 14 consecutive failed logins
  between 01:47 and 01:55 should have triggered a brute-force lockout. If an
  alert had fired then, the account would never have authenticated.
- **Earliest log source**: Authentication logs (`attack_sequence.jsonl`)

### Part 7C – STRIDE alignment

| Event | STRIDE category |
|-------|-----------------|
| Credential brute-force | **Spoofing** |
| `buildspec.yml` pipeline tampering | **Tampering** |
| Bulk data download via analyst account | **Information Disclosure** |
| SAST gate bypass enabling malicious deploy | **Tampering** / **Elevation of Privilege** |
| No artifact signing | **Tampering** (mitigation gap) |

Teaching note: All of these should appear in the STRIDE threat register from
Lab 6. If mitigations were marked as "implemented" for spoofing/tampering but
this attack succeeded, that is a finding for the post-incident review.

---

## Key Teaching Moments

1. **The alert came too late.** The build artifact anomaly at 02:44 was the trigger,
   but the account was compromised 57 minutes earlier. Better detection at the
   authentication layer would have prevented everything downstream.

2. **A logged warning that allows the pipeline to continue is not a security control.**
   The SAST gate wrote a `WARN` and continued. Students should be challenged: *what
   is the point of a gate that opens anyway?*

3. **STRIDE predicted this.** The threat model identified spoofing and pipeline
   tampering as risks. This lab demonstrates what those threats look like in practice.

# 06 — Threat Prioritisation (DREAD Scoring)

## Scoring Key

| Dimension | 1 — Low | 2 — Medium | 3 — High |
|-----------|---------|-----------|---------|
| **D**amage | Minimal / cosmetic | Significant data loss or service degradation | Full compromise, data exfiltration, regulatory breach |
| **R**eproducibility | Requires rare conditions | Repeatable with effort | Trivially repeatable |
| **E**xploitability | Expert attacker, physical access | Skilled attacker, network access | Script kiddie, public exploit available |
| **A**ffected users | Single user | Subset of users | All users / entire system |
| **D**iscoverability | Hidden, requires source access | Detectable with scanning | Exposed in public API / documentation |

**DREAD Total** = D + R + E + A + D (max 15)

| Risk Band | Score | Action |
|-----------|-------|--------|
| 🔴 Critical | 13–15 | Fix before deploy |
| 🟠 High | 10–12 | Fix in current sprint |
| 🟡 Medium | 7–9 | Fix in next sprint |
| 🟢 Low | ≤6 | Accept / monitor |

---

## DREAD Scores — All 34 Threats

> Threats sourced from `03-stride-analysis.md`.  
> Boundary codes: TB-1 Internet→API GW · TB-2 API GW→Lambda · TB-3 Lambda→DynamoDB · TB-4 Lambda→CloudWatch · TB-5 Admin→AWS Console

### Spoofing (S)

| ID | Title | D | R | E | A | D | Total | Band |
|----|-------|---|---|---|---|---|-------|------|
| T-01 | JWT replay attack | 3 | 2 | 2 | 3 | 2 | **12** | 🟠 High |
| T-02 | Stolen Cognito credentials | 3 | 2 | 2 | 2 | 2 | **11** | 🟠 High |
| T-03 | Forged JWT signature | 3 | 1 | 1 | 3 | 1 | **9** | 🟡 Medium |
| T-04 | Lambda execution role impersonation | 3 | 1 | 1 | 3 | 1 | **9** | 🟡 Medium |
| T-05 | Cognito user pool enumeration | 2 | 3 | 3 | 3 | 3 | **14** | 🔴 Critical |
| T-06 | CloudTrail identity spoofing | 2 | 1 | 1 | 3 | 1 | **8** | 🟡 Medium |

### Tampering (T)

| ID | Title | D | R | E | A | D | Total | Band |
|----|-------|---|---|---|---|---|-------|------|
| T-07 | HTTP request body tampering | 2 | 3 | 3 | 2 | 3 | **13** | 🔴 Critical |
| T-08 | DynamoDB record manipulation | 3 | 1 | 1 | 3 | 1 | **9** | 🟡 Medium |
| T-09 | Environment variable injection | 3 | 1 | 2 | 3 | 1 | **10** | 🟠 High |
| T-10 | Log tampering / deletion | 2 | 1 | 2 | 3 | 1 | **9** | 🟡 Medium |
| T-11 | S3 build artefact tampering | 3 | 1 | 2 | 3 | 1 | **10** | 🟠 High |
| T-12 | SAM template parameter injection | 3 | 1 | 2 | 3 | 2 | **11** | 🟠 High |

### Repudiation (R)

| ID | Title | D | R | E | A | D | Total | Band |
|----|-------|---|---|---|---|---|-------|------|
| T-13 | Missing audit trail for writes | 2 | 3 | 3 | 3 | 2 | **13** | 🔴 Critical |
| T-14 | Log stream deletion | 2 | 1 | 2 | 3 | 1 | **9** | 🟡 Medium |
| T-15 | CloudTrail disabled | 3 | 1 | 2 | 3 | 1 | **10** | 🟠 High |
| T-16 | X-Ray trace gap (cold start) | 1 | 2 | 3 | 2 | 2 | **10** | 🟠 High |

### Information Disclosure (I)

| ID | Title | D | R | E | A | D | Total | Band |
|----|-------|---|---|---|---|---|-------|------|
| T-17 | Sensitive data in Lambda logs | 2 | 2 | 2 | 3 | 2 | **11** | 🟠 High |
| T-18 | DynamoDB table exposed via over-permissive IAM | 3 | 1 | 1 | 3 | 1 | **9** | 🟡 Medium |
| T-19 | Error messages leaking stack traces | 2 | 3 | 3 | 3 | 3 | **14** | 🔴 Critical |
| T-20 | Unencrypted data in transit (misconfigured client) | 3 | 1 | 2 | 3 | 1 | **10** | 🟠 High |
| T-21 | CloudWatch log export without encryption | 2 | 1 | 2 | 3 | 1 | **9** | 🟡 Medium |
| T-22 | API GW response caching leaking cross-user data | 2 | 2 | 2 | 3 | 2 | **11** | 🟠 High |
| T-23 | S3 artefact bucket public read | 3 | 1 | 2 | 3 | 2 | **11** | 🟠 High |

### Denial of Service (D)

| ID | Title | D | R | E | A | D | Total | Band |
|----|-------|---|---|---|---|---|-------|------|
| T-24 | API GW flood (unauthenticated) | 3 | 3 | 3 | 3 | 3 | **15** | 🔴 Critical |
| T-25 | Lambda concurrency exhaustion | 2 | 2 | 2 | 3 | 2 | **11** | 🟠 High |
| T-26 | DynamoDB hot-partition attack | 2 | 2 | 2 | 2 | 2 | **10** | 🟠 High |
| T-27 | Oversized request payload | 2 | 3 | 3 | 2 | 3 | **13** | 🔴 Critical |
| T-28 | CloudWatch log ingestion exhaustion | 1 | 2 | 2 | 2 | 2 | **9** | 🟡 Medium |

### Elevation of Privilege (E)

| ID | Title | D | R | E | A | D | Total | Band |
|----|-------|---|---|---|---|---|-------|------|
| T-29 | Analyst→Admin privilege escalation via Cognito group manipulation | 3 | 2 | 2 | 3 | 2 | **12** | 🟠 High |
| T-30 | Lambda escape to host (supply-chain RCE) | 3 | 1 | 1 | 3 | 1 | **9** | 🟡 Medium |
| T-31 | IAM privilege escalation via Lambda role | 3 | 1 | 2 | 3 | 1 | **10** | 🟠 High |
| T-32 | CodeBuild role over-privilege | 3 | 1 | 2 | 3 | 2 | **11** | 🟠 High |
| T-33 | Dependency confusion attack | 3 | 2 | 2 | 3 | 2 | **12** | 🟠 High |
| T-34 | JWT claims manipulation (custom attributes) | 3 | 1 | 2 | 3 | 1 | **10** | 🟠 High |

---

## Priority Summary

| Band | Count | Threat IDs |
|------|-------|------------|
| 🔴 Critical (13–15) | 6 | T-05, T-07, T-13, T-19, T-24, T-27 |
| 🟠 High (10–12) | 16 | T-01, T-02, T-09, T-11, T-12, T-15, T-16, T-17, T-20, T-22, T-23, T-25, T-26, T-29, T-31, T-32, T-33, T-34 |
| 🟡 Medium (7–9) | 10 | T-03, T-04, T-06, T-08, T-10, T-14, T-18, T-21, T-28, T-30 |
| 🟢 Low (≤6) | 2 | — |

> **Treatment order:** Critical → High → Medium → Low.  
> See `07-mitigations-and-validation.md` for remediation details.

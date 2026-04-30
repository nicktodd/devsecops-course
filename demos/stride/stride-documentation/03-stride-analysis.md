# STRIDE Analysis — 03: STRIDE Applied to Model Elements

For each trust boundary and key component, we apply all six STRIDE categories.
Each threat is given a unique ID (T-XX) for traceability to abuse cases and mitigations.

---

## TB-1: Public Internet → API Gateway

| ID | STRIDE | Threat Description | Existing Control | Gap? |
|---|---|---|---|---|
| T-01 | **Spoofing** | Attacker presents a forged or stolen JWT to impersonate a legitimate user | Cognito validates JWT signature, expiry (1hr), and issuer | ⚠️ Stolen valid token has no revocation mechanism |
| T-02 | **Spoofing** | Attacker attempts to enumerate valid user email addresses via auth error messages | `PreventUserExistenceErrors: ENABLED` on Cognito client | ✅ |
| T-03 | **Tampering** | Attacker sends a malformed or oversized request body to exploit a parsing bug | API Gateway max payload + Lambda input validation | ✅ |
| T-04 | **Repudiation** | Attacker makes requests and claims they were not the caller | API Gateway access logs capture IP, user, method, path | ✅ |
| T-05 | **Information Disclosure** | Error responses reveal internal stack traces or infrastructure details | Lambda catches all exceptions and returns generic 500 | ✅ |
| T-06 | **Denial of Service** | Attacker floods the API to exhaust Lambda concurrency or API GW quota | Throttling: 20 rps / 50 burst; Lambda auto-scales but has account concurrency limit | ⚠️ No WAF; account-level concurrency limit shared with other functions |
| T-07 | **Elevation of Privilege** | Unauthenticated caller accesses endpoints by omitting the Authorization header | Cognito authorizer enforces auth on all routes by default | ✅ |

---

## TB-2: API Gateway → Lambda (post-authentication)

| ID | STRIDE | Threat Description | Existing Control | Gap? |
|---|---|---|---|---|
| T-08 | **Spoofing** | Lambda trusts injected claims blindly — if API GW were bypassed, claims could be forged | Lambda is not publicly accessible; only invocable via API GW resource policy | ✅ |
| T-09 | **Tampering** | Attacker injects SQL/NoSQL injection via request body fields | DynamoDB uses parameterised `Key` and `Item` structures — no query interpolation | ✅ |
| T-10 | **Tampering** | Attacker sends a negative `launchYear` or an invalid `status` to corrupt data integrity | `validate_mission_input()` enforces type, range, and allowlist checks | ✅ |
| T-11 | **Repudiation** | A write operation is performed but the caller's identity is not recorded | `createdBy` / `updatedBy` fields written with `caller["email"]` on every mutation | ✅ |
| T-12 | **Information Disclosure** | Lambda logs include full request body containing sensitive payload data | `DataTraceEnabled: false` on API GW; Lambda logs strip body from log lines | ✅ |
| T-13 | **Denial of Service** | Attacker sends valid but expensive `Scan` requests to exhaust DynamoDB read capacity | Pagination enforced (`MAX_PAGE_SIZE = 50`); on-demand billing absorbs spikes | ⚠️ Scan is still O(table size) — could be expensive at scale |
| T-14 | **Elevation of Privilege** | `analyst` user calls a write endpoint (POST/PUT/DELETE) | `caller_has_write_access()` checks `cognito:groups` claim; returns 403 if not admin | ✅ |
| T-15 | **Elevation of Privilege** | Attacker tampers with the `cognito:groups` claim in the JWT payload | JWT is RS256 signed by Cognito — payload cannot be altered without invalidating signature | ✅ |

---

## TB-3: Lambda → DynamoDB

| ID | STRIDE | Threat Description | Existing Control | Gap? |
|---|---|---|---|---|
| T-16 | **Spoofing** | Lambda assumes a different role to gain wider DynamoDB access | IAM role is explicitly assigned; Lambda cannot assume arbitrary roles | ✅ |
| T-17 | **Tampering** | Attacker with Lambda execution access directly modifies DynamoDB records | DynamoDB SSE + PITR — data is encrypted and recoverable; CloudTrail records API calls | ✅ |
| T-18 | **Repudiation** | DynamoDB write has no record of which user triggered it | `createdBy` / `updatedBy` stored in item; CloudWatch Lambda logs tie back to caller | ✅ |
| T-19 | **Information Disclosure** | DynamoDB data at rest is readable if storage is compromised | SSE-AES256 enabled on all three tables | ✅ |
| T-20 | **Denial of Service** | Lambda performs unbounded `Scan` on large table causing throttling | `Limit` parameter passed on every scan; DynamoDB on-demand handles burst | ⚠️ No DynamoDB auto-scaling alarm |
| T-21 | **Elevation of Privilege** | Lambda role has overly broad DynamoDB permissions (wildcard resource) | Role scoped to specific table ARNs, specific actions only | ✅ |

---

## TB-4: CodeBuild → Lambda Deployment

| ID | STRIDE | Threat Description | Existing Control | Gap? |
|---|---|---|---|---|
| T-22 | **Spoofing** | A malicious actor triggers a build using stolen AWS credentials | CodeBuild uses IAM role — no long-lived access keys; triggered via webhook | ⚠️ No MFA on pipeline trigger |
| T-23 | **Tampering** | Attacker modifies `buildspec.yml` to inject malicious build steps | `buildspec.yml` is in source control; changes require PR approval (branch protection) | ⚠️ Branch protection not enforced by this template |
| T-24 | **Tampering** | A compromised dependency (`requirements.txt`) introduces malicious code | `pip-audit` scans for known CVEs; `bandit` scans for SAST issues | ⚠️ No hash pinning on pip dependencies |
| T-25 | **Repudiation** | A deploy occurs with no record of who approved it | CloudWatch CodeBuild logs; GitHub commit history; no formal approval gate | ⚠️ No manual approval step before prod deploy |
| T-26 | **Information Disclosure** | Build logs expose secrets (e.g. AWS account ID, API endpoints) | CodeBuild logs encrypted; SSM Parameter Store used for secrets in buildspec | ✅ |
| T-27 | **Denial of Service** | Pipeline is spammed with builds exhausting CodeBuild minutes or concurrency | Webhook filters to `main` branch pushes and PRs only | ✅ |
| T-28 | **Elevation of Privilege** | CodeBuild role has wildcard Lambda/CloudFormation permissions | Role is scoped to named stack ARN and Lambda resources; reviewed in `pipeline.yaml` | ⚠️ `lambda:*` and `apigateway:*` are broad |

---

## TB-5: GitHub → CodeBuild (Supply Chain)

| ID | STRIDE | Threat Description | Existing Control | Gap? |
|---|---|---|---|---|
| T-29 | **Spoofing** | Attacker impersonates a developer and pushes to `main` | CodeConnections OAuth; GitHub authentication | ⚠️ No branch protection enforced by this repo's settings |
| T-30 | **Tampering** | Malicious dependency injected via a typosquatted package name in `requirements.txt` | `pip-audit` checks known CVEs but not typosquatting | ⚠️ No package hash pinning; no private mirror |
| T-31 | **Repudiation** | A commit is pushed to `main` without a review trail | GitHub commit history; no mandatory PR review enforced in template | ⚠️ |
| T-32 | **Information Disclosure** | Secrets accidentally committed to the repository | No secrets in code (SSM used); `bandit` would flag hardcoded strings | ✅ |
| T-33 | **Denial of Service** | Force-push to `main` breaks the build permanently | GitHub branch protection (recommended) | ⚠️ Not enforced by this template |
| T-34 | **Elevation of Privilege** | Attacker gains write access to GitHub repo and deploys malicious Lambda code | Two-factor auth on GitHub (recommended); CodeConnections scoped to repo | ⚠️ 2FA enforcement is GitHub org setting — outside this template |

---

## Gap Summary

| ID | Gap | Recommended Fix |
|---|---|---|
| T-01 | No JWT revocation | Enable Cognito advanced security + token revocation on sign-out |
| T-06 | No WAF | Add AWS WAF to API Gateway with rate-based rules |
| T-13 | Scan can be expensive | Replace `Scan` with GSI-based `Query` at scale |
| T-23 | No branch protection | Enforce PR reviews + branch protection on `main` in GitHub |
| T-24 | No hash pinning | Use `pip-compile` with hash pinning (`--generate-hashes`) |
| T-25 | No approval gate | Add a manual approval action in CodePipeline before prod |
| T-28 | Broad CodeBuild IAM | Scope `lambda:*` to specific function ARNs |
| T-29 | No branch protection | Enforce required reviewers via GitHub branch protection rules |
| T-30 | Typosquatting | Use a private PyPI mirror or Codeartifact |

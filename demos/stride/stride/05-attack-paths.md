# STRIDE Analysis — 05: Attack Paths

Attack trees show how an attacker could achieve a goal, broken down into steps.
Each tree maps to one or more abuse cases from `04-abuse-cases.md`.

---

## AT-01: Gain Unauthorised Read Access to Mission Data

**Goal:** Read ESA mission records without a valid account  
**Related abuse cases:** AC-02, AC-01

```mermaid
flowchart TD
    Goal["🎯 Read mission data\nwithout authorisation"]

    Goal --> A["Path A:\nBypass authentication entirely"]
    Goal --> B["Path B:\nUse a stolen valid token"]
    Goal --> C["Path C:\nExploit misconfigured endpoint"]

    A --> A1["Call API with no\nAuthorization header"]
    A --> A2["Forge a JWT with\na known secret"]
    A1 -->|"Blocked by\nCognito Authorizer"| A1R["❌ 401 Unauthorised"]
    A2 -->|"Blocked - RS256\nCognito-signed"| A2R["❌ 401 Unauthorised"]

    B --> B1["Intercept token from\ncompromised device"]
    B --> B2["Phish user credentials\nvia fake login page"]
    B1 --> B1a["Replay token within\n1-hour window"]
    B2 --> B2a["Log in as victim\nvia Cognito"]
    B1a -->|"No revocation\nmechanism"| B1R["⚠️ Succeeds until\ntoken expires"]
    B2a -->|"MFA not mandatory"| B2R["⚠️ Succeeds if\nno MFA enabled"]

    C --> C1["Find endpoint with\nauth disabled"]
    C1 -->|"All routes use\ndefault authorizer"| C1R["❌ Blocked"]
```

---

## AT-02: Escalate from Analyst to Admin Privileges

**Goal:** Perform write operations as a read-only analyst  
**Related abuse cases:** AC-03, AC-04

```mermaid
flowchart TD
    Goal["🎯 Write mission data\nas analyst user"]

    Goal --> A["Path A:\nBypass RBAC check in Lambda"]
    Goal --> B["Path B:\nTamper with JWT claims"]
    Goal --> C["Path C:\nCompromise an admin account"]

    A --> A1["Call POST/PUT/DELETE\nwith analyst JWT"]
    A1 -->|"caller_has_write_access()\nchecks cognito:groups"| A1R["❌ 403 Forbidden"]

    B --> B1["Decode JWT payload\n(base64)"]
    B1 --> B2["Modify cognito:groups\nto 'admin'"]
    B2 --> B3["Re-encode and\nsubmit token"]
    B3 -->|"RS256 signature\nnow invalid"| B3R["❌ 401 Unauthorised\nfrom Cognito Authorizer"]

    C --> C1["Phish admin user\ncredentials"]
    C --> C2["Credential stuffing\nagainst Cognito"]
    C1 --> C1a["Authenticate as admin"]
    C2 -->|"SRP auth prevents\npassword brute-force"| C2R["❌ Blocked by SRP"]
    C1a -->|"MFA check"| C1b{"MFA\nenabled?"}
    C1b -->|"Yes"| C1bY["❌ Blocked\nby MFA"]
    C1b -->|"No (optional)"| C1bN["⚠️ Admin access\nachieved"]
```

---

## AT-03: Inject Malicious Code via the Build Pipeline

**Goal:** Deploy backdoored Lambda code to production  
**Related abuse cases:** AC-07, AC-08

```mermaid
flowchart TD
    Goal["🎯 Deploy malicious\nLambda code"]

    Goal --> A["Path A:\nModify buildspec.yml"]
    Goal --> B["Path B:\nPoison a pip dependency"]
    Goal --> C["Path C:\nCompromise CodeBuild IAM role"]

    A --> A1["Gain write access\nto GitHub repo"]
    A1 --> A2{"Branch protection\nenforced?"}
    A2 -->|"No"| A2N["Push directly to main"]
    A2 -->|"Yes"| A2Y["Open PR with\nmalicious change"]
    A2N --> A3["CodeBuild executes\nmodified buildspec"]
    A2Y --> A4{"PR review\nspots the change?"}
    A4 -->|"No"| A3
    A4 -->|"Yes"| A4R["❌ PR rejected"]
    A3 --> A5["⚠️ Malicious code\ndeployed to Lambda"]

    B --> B1["Publish typosquatted\npackage to PyPI"]
    B1 --> B2["Submit PR changing\nrequirements.txt"]
    B2 --> B3{"pip-audit\ndetects it?"}
    B3 -->|"Known CVE"| B3Y["❌ Build fails"]
    B3 -->|"Unknown / new"| B3N["⚠️ Package installed\nduring build"]
    B3N --> B4{"Hash pinning\nenabled?"}
    B4 -->|"Yes"| B4Y["❌ Hash mismatch\nfails install"]
    B4 -->|"No"| B4N["⚠️ Malicious package\nexecutes at build time"]

    C --> C1["Steal CodeBuild\nIAM role credentials"]
    C1 -->|"Role uses instance\nprofile - no static keys"| C1R["❌ No static\ncredentials to steal"]
```

---

## AT-04: Cause Denial of Service

**Goal:** Make the API unavailable to legitimate users  
**Related abuse cases:** AC-06

```mermaid
flowchart TD
    Goal["🎯 Deny API access\nto legitimate users"]

    Goal --> A["Path A:\nFlood with unauthenticated requests"]
    Goal --> B["Path B:\nFlood with authenticated requests"]
    Goal --> C["Path C:\nExhaust DynamoDB capacity"]

    A --> A1["Send thousands of\nrequests/sec to API GW"]
    A1 --> A2{"API GW throttle\nhit (20rps)?"}
    A2 -->|"Yes"| A2Y["429 returned\nto attacker"]
    A2 -->|"Before throttle\nkicks in"| A2N["⚠️ Some requests\nreach Lambda"]
    A2Y --> A3{"Legitimate user\naffected?"}
    A3 -->|"Shared throttle\nper account"| A3Y["⚠️ Possible impact\nwithout WAF"]

    B --> B1["Obtain valid JWT"]
    B1 --> B2["Send bulk authenticated\nGET /missions requests"]
    B2 --> B3{"Throttle hit?"}
    B3 -->|"Yes"| B3Y["429 - attacker throttled\nbut quota shared"]

    C --> C1["Authenticated user\nsends GET /missions"]
    C1 --> C2["Scan executes\non large table"]
    C2 -->|"limit=50 enforced"| C2R["⚠️ Reduced impact\nbut still O(n)"]
```

---

## AT-05: Exfiltrate Mission Intelligence

**Goal:** Extract all ESA mission data  
**Related abuse cases:** AC-09, AC-01

```mermaid
flowchart TD
    Goal["🎯 Export all ESA\nmission records"]

    Goal --> A["Path A:\nAuthenticated bulk read\nvia pagination"]
    Goal --> B["Path B:\nDirect DynamoDB\naccess"]

    A --> A1["Authenticate as\nany valid user"]
    A1 --> A2["Call GET /missions?limit=50"]
    A2 --> A3["Follow nextToken\nthrough all pages"]
    A3 --> A4["Aggregate all records"]
    A4 -->|"No row-level access\ncontrol exists"| A4R["⚠️ All records exported\nby any auth user"]

    B --> B1["Obtain AWS credentials\nwith DynamoDB access"]
    B1 --> B2{"Credentials\navailable?"}
    B2 -->|"Lambda role\nnot exposed"| B2N["❌ No direct\nDynamoDB access"]
    B2 -->|"Via pipeline\ncompromise (AT-03)"| B2Y["⚠️ Direct table\nscan possible"]
```

---

## Attack Path Risk Summary

| Tree | Goal | Easiest Path | Difficulty | Current Status |
|---|---|---|---|---|
| AT-01 | Unauthorised read | Stolen token replay | Medium | ⚠️ Partial — no revocation |
| AT-02 | Analyst → Admin EoP | Phish admin + no MFA | Medium | ⚠️ MFA is optional |
| AT-03 | Backdoor Lambda | Modify buildspec.yml | Hard | ⚠️ Branch protection not enforced |
| AT-04 | DoS | Authenticated request flood | Easy | ⚠️ No WAF |
| AT-05 | Data exfiltration | Authenticated pagination | Easy | ⚠️ No row-level access control |

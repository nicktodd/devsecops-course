# STRIDE Analysis — 00: Scope and Goals

## Application Under Review

**ESA Mission Registry API** — a serverless REST API for tracking European Space Agency
missions, satellites, and launch events. Built with AWS Lambda, API Gateway, Cognito,
and DynamoDB.

---

## Scope

### In Scope

| Component | Description |
|---|---|
| API Gateway | Regional REST API endpoint, Cognito authorizer, throttling |
| Cognito User Pool | Authentication, JWT issuance, user groups (admin/analyst) |
| Lambda Functions | `missions.py`, `satellites.py`, `launches.py` |
| DynamoDB Tables | `esa-missions`, `esa-satellites`, `esa-launches` |
| IAM Role | Lambda execution role with DynamoDB permissions |
| CloudWatch Logs | API access logs, Lambda logs |
| CodeBuild Pipeline | Build, test, scan, and deploy pipeline |
| S3 Artifact Bucket | Build artefacts and SAM packaged templates |

### Out of Scope

| Component | Reason |
|---|---|
| AWS underlying infrastructure | Assumed trusted; AWS responsible under shared responsibility model |
| GitHub repository | External system; supply chain threats noted but not fully modelled |
| Developer workstations | Outside AWS boundary |
| AWS Console access | IAM / SSO controls are a separate concern |
| DDoS at network layer | AWS Shield covers this at the platform level |

---

## Security Objectives

Applying the **CIA triad** to mission registry data:

| Objective | Description | Example |
|---|---|---|
| **Confidentiality** | Mission data must only be accessible to authenticated users | An unauthenticated caller must not retrieve mission records |
| **Integrity** | Mission data must not be altered by unauthorised parties | An `analyst` must not be able to create or delete a mission |
| **Availability** | The API must remain available under normal and moderately elevated load | A single caller must not be able to take the API offline |

### Additional Security Goals

- **Non-repudiation** — all write operations must be traceable to an authenticated identity
- **Least privilege** — each component holds only the permissions it needs to function
- **Defence in depth** — threats are mitigated at multiple layers, not just the perimeter

---

## Assumptions

1. AWS platform controls (physical security, hypervisor isolation, managed service patching) are trusted.
2. Cognito correctly validates JWTs — we trust the AWS-managed signing keys.
3. TLS termination at API Gateway is trusted; traffic inside AWS is not intercepted.
4. The AWS account has CloudTrail enabled (account-level audit — not modelled here but assumed).
5. Developers follow least-privilege IAM practices for their own credentials.
6. The CodeStar/CodeConnections GitHub connection has been authorised by an account owner.

---

## Threat Modelling Goals

1. Identify threats specific to this serverless architecture.
2. Ensure all six STRIDE categories are considered at each trust boundary.
3. Produce actionable abuse cases that can be turned into tests.
4. Verify that existing mitigations in `template.yaml` and the Lambda handlers adequately address each threat.
5. Identify any gaps where additional controls are needed.

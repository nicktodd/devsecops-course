# 07 — Mitigations and Validation

## How to Use This Document

Each threat from `03-stride-analysis.md` is mapped to:

1. **Mitigation** — the control or code change that eliminates or reduces the threat.
2. **Implementation pointer** — where in the codebase / infrastructure the control lives.
3. **Validation step** — how to confirm the control works.
4. **Test evidence** — automated test or AWS Config rule that provides ongoing assurance.

Controls that apply to multiple threats are described once and referenced by ID.

---

## Control Library

| Ctrl ID | Name | Type |
|---------|------|------|
| C-01 | Short-lived JWT + Cognito authorizer on every route | Preventive |
| C-02 | MFA enforced in Cognito User Pool | Preventive |
| C-03 | HTTPS-only API Gateway (TLS 1.2 minimum) | Preventive |
| C-04 | Input validation in Lambda handlers (size, type, regex) | Preventive |
| C-05 | Least-privilege Lambda IAM role (per-table, per-action) | Preventive |
| C-06 | DynamoDB encryption at rest (SSE-KMS) | Preventive |
| C-07 | DynamoDB Point-in-Time Recovery (PITR) | Recovery |
| C-08 | CloudWatch log retention + KMS encryption | Detective / Preventive |
| C-09 | CloudTrail multi-region trail + S3 log integrity | Detective |
| C-10 | API Gateway throttling (rate + burst limits) | Preventive |
| C-11 | Lambda reserved concurrency per function | Preventive |
| C-12 | Structured JSON logging (no PII / secrets) | Preventive |
| C-13 | RBAC enforced in handler (Cognito `cognito:groups` claim) | Preventive |
| C-14 | Generic error responses (no stack traces to caller) | Preventive |
| C-15 | S3 artefact bucket — block public access + SSE-S3 | Preventive |
| C-16 | CodeBuild IAM role scoped to minimum required actions | Preventive |
| C-17 | Dependency pinning + hash verification in `requirements.txt` | Preventive |
| C-18 | Bandit SAST in pre_build phase (CodeBuild) | Detective |
| C-19 | AWS WAF on API Gateway (rate rule + AWS managed rules) | Preventive |
| C-20 | Security Hub + GuardDuty enabled | Detective |
| C-21 | Cognito `PreAuthentication` Lambda trigger (account lockout) | Preventive |
| C-22 | X-Ray tracing on all Lambda functions and API GW | Detective |
| C-23 | DynamoDB write-through audit fields (`created_by`, `updated_at`) | Detective |
| C-24 | AWS Config rules (cloudtrail-enabled, mfa-enabled-for-iam-console-access) | Detective |

---

## Mitigation Mapping

### Spoofing

| Threat | Title | Controls | Residual Risk |
|--------|-------|----------|---------------|
| T-01 | JWT replay attack | C-01 (1 h token TTL), C-22 (trace anomalous replay) | Low — replay window ≤ 1 h |
| T-02 | Stolen Cognito credentials | C-02 (MFA), C-21 (lockout) | Low |
| T-03 | Forged JWT signature | C-01 (Cognito authorizer validates RS256 signature against JWKS) | Very Low |
| T-04 | Lambda execution role impersonation | C-05 (role not assumable from outside VPC/CodeBuild context) | Low |
| T-05 | Cognito user pool enumeration | C-21, C-19 (WAF rate limit on `/token` endpoint) | Medium — enumeration still partially possible without `PreventUserExistenceErrors` |
| T-06 | CloudTrail identity spoofing | C-09 (log file integrity validation enabled) | Low |

**Gap — T-05:** Enable `PreventUserExistenceErrors` in the Cognito User Pool.  
Add to `template.yaml`:
```yaml
UserPoolAddOns:
  AdvancedSecurityMode: AUDIT
PreventUserExistenceErrors: ENABLED   # under UserPool Policies
```

---

### Tampering

| Threat | Title | Controls | Residual Risk |
|--------|-------|----------|---------------|
| T-07 | HTTP request body tampering | C-04 (schema validation), C-03 (TLS in transit) | Low |
| T-08 | DynamoDB record manipulation | C-05 (deny `dynamodb:*` except explicit actions), C-06 | Low |
| T-09 | Environment variable injection | C-05 (deny `lambda:UpdateFunctionConfiguration` to app role) | Low |
| T-10 | Log tampering / deletion | C-08 (deny `logs:DeleteLogGroup` to app role), C-09 | Low |
| T-11 | S3 build artefact tampering | C-15 (block public + SSE), C-09 (S3 object-level events in CloudTrail) | Low |
| T-12 | SAM template parameter injection | C-16 (CodeBuild role cannot call `iam:PassRole` to arbitrary roles) | Low |

---

### Repudiation

| Threat | Title | Controls | Residual Risk |
|--------|-------|----------|---------------|
| T-13 | Missing audit trail for writes | C-23 (handler writes `created_by` / `updated_by`), C-09 | Low |
| T-14 | Log stream deletion | C-08 (resource-based deny on `logs:DeleteLogStream`), C-09 | Low |
| T-15 | CloudTrail disabled | C-24 (`cloudtrail-enabled` Config rule → SNS alert) | Low |
| T-16 | X-Ray trace gap (cold start) | C-22 (Lambda power-tools tracer wraps handler) | Medium — very first invocation still has gap |

---

### Information Disclosure

| Threat | Title | Controls | Residual Risk |
|--------|-------|----------|---------------|
| T-17 | Sensitive data in Lambda logs | C-12 (structured logger strips PII fields), C-18 (Bandit flags `print` with secrets) | Low |
| T-18 | DynamoDB table exposed via over-permissive IAM | C-05 (each Lambda has its own role scoped to its table) | Low |
| T-19 | Error messages leaking stack traces | C-14 (`except Exception: return 500 {"message":"Internal error"}`) | Low |
| T-20 | Unencrypted data in transit | C-03 (API GW rejects HTTP; SDK uses HTTPS by default) | Low |
| T-21 | CloudWatch log export without encryption | C-08 (log group KMS key ARN set in template) | Low |
| T-22 | API GW response caching leaking cross-user data | Caching disabled on all routes (default in current template) | Low |
| T-23 | S3 artefact bucket public read | C-15 (`BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets: true`) | Very Low |

---

### Denial of Service

| Threat | Title | Controls | Residual Risk |
|--------|-------|----------|---------------|
| T-24 | API GW flood (unauthenticated) | C-10 (throttling), C-19 (WAF rate rule 2000 req/5 min per IP) | Medium — sustained volumetric still needs AWS Shield Advanced |
| T-25 | Lambda concurrency exhaustion | C-11 (`ReservedConcurrentExecutions: 50` per function) | Low |
| T-26 | DynamoDB hot-partition attack | C-04 (validate `mission_id` format); DynamoDB on-demand capacity | Low |
| T-27 | Oversized request payload | C-04 (max body size check in handler); API GW 10 MB hard limit | Low |
| T-28 | CloudWatch log ingestion exhaustion | C-12 (structured logs only; no debug verbosity in prod) | Low |

**Gap — T-24:** AWS WAF not yet wired to the API Gateway in `template.yaml`.  
Add to `template.yaml` (under `Globals` or as a separate `AWS::WAFv2::WebACLAssociation` resource):
```yaml
  MissionApiWafAssociation:
    Type: AWS::WAFv2::WebACLAssociation
    Properties:
      ResourceArn: !Sub "arn:aws:apigateway:${AWS::Region}::/restapis/${MissionApi}/stages/Prod"
      WebACLArn: !Ref MissionApiWAF
```

---

### Elevation of Privilege

| Threat | Title | Controls | Residual Risk |
|--------|-------|----------|---------------|
| T-29 | Analyst→Admin via Cognito group manipulation | C-13 (RBAC checked inside Lambda, not just at authorizer layer) | Low |
| T-30 | Lambda escape to host (supply-chain RCE) | C-17 (pinned deps), C-18 (Bandit), C-20 (GuardDuty) | Medium — serverless isolation is strong but supply chain still a vector |
| T-31 | IAM privilege escalation via Lambda role | C-05 (`iam:PassRole` deny in Lambda role boundary) | Low |
| T-32 | CodeBuild role over-privilege | C-16 (scoped to `s3:PutObject` on artefact bucket, `cloudformation:*` on stack prefix only) | Low |
| T-33 | Dependency confusion attack | C-17 (hash pinning + private PyPI mirror or CodeArtifact) | Medium — CodeArtifact not yet configured |
| T-34 | JWT claims manipulation (custom attributes) | C-01 (authorizer validates `iss` and `aud`; handler validates `cognito:groups` not custom attr) | Low |

---

## Validation Steps

### Automated Tests (`tests/test_handlers.py`)

| Test | Threat(s) Covered |
|------|------------------|
| `test_create_mission_unauthorized` | T-01, T-29 (no token → 403) |
| `test_create_mission_analyst_forbidden` | T-29 (analyst role → 403 on write) |
| `test_create_mission_success` | T-07 (valid body → 201) |
| `test_get_mission_not_found` | T-14 (generic 404, no stack trace) |
| `test_oversized_payload` | T-27 (body > limit → 400) |
| `test_list_missions` | T-22 (no cross-user data in list response) |
| `test_audit_fields_written` | T-13 (`created_by` present in DynamoDB record) |

Run:
```bash
pytest tests/ -v --cov=app/src --cov-report=term-missing
```

### Manual / Pipeline Validation Checklist

| # | Check | How | Expected Result |
|---|-------|-----|----------------|
| 1 | Cognito JWT TTL | Decode token with `jwt.io` | `exp - iat = 3600` s |
| 2 | MFA enforcement | Create user without MFA, attempt login | Cognito blocks login with `SOFTWARE_TOKEN_MFA_NOT_ENABLED` |
| 3 | TLS enforcement | `curl http://<api-gw-url>/missions` | `301` redirect or connection refused |
| 4 | Input validation — oversized body | POST 1 MB JSON body | `400 Bad Request` |
| 5 | Throttling | Apache Bench: `ab -n 10000 -c 100 GET /missions` | `429` responses after burst limit |
| 6 | IAM least-privilege | AWS IAM Access Analyzer on Lambda role | Zero unused permissions (target: green) |
| 7 | CloudTrail integrity | `aws cloudtrail validate-logs --trail-arn <arn> --start-time <t>` | `No invalid log files found` |
| 8 | Error message sanitisation | Send `{"mission_id": "'; DROP TABLE missions; --"}` | `400` with `{"message":"Validation error"}`, no SQL/stack trace |
| 9 | Bandit SAST | `bandit -r app/src/` | Zero HIGH severity findings |
| 10 | S3 bucket public access | `aws s3api get-public-access-block --bucket <artefact-bucket>` | All four flags `true` |
| 11 | DynamoDB encryption | `aws dynamodb describe-table --table-name Missions` | `SSEDescription.Status = ENABLED` |
| 12 | PITR | `aws dynamodb describe-continuous-backups --table-name Missions` | `ContinuousBackupsStatus = ENABLED` |
| 13 | GuardDuty | AWS Console → GuardDuty → Findings | No HIGH findings in steady state |

### AWS Config Rules

Add the following managed Config rules to `pipeline.yaml` or a dedicated `config-rules.yaml`:

```yaml
  CloudTrailEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cloudtrail-enabled
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_ENABLED

  MFAEnabledForIAMConsoleAccess:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: mfa-enabled-for-iam-console-access
      Source:
        Owner: AWS
        SourceIdentifier: MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS

  DynamoDBTableEncryptionEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: dynamodb-table-encrypted-at-rest
      Source:
        Owner: AWS
        SourceIdentifier: DYNAMODB_TABLE_ENCRYPTED_AT_REST

  S3BucketPublicReadProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-public-read-prohibited
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_READ_PROHIBITED

  LambdaFunctionPublicAccessProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: lambda-function-public-access-prohibited
      Source:
        Owner: AWS
        SourceIdentifier: LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED
```

---

## Residual Risk Register

| Threat | Residual Risk | Owner | Review Date |
|--------|--------------|-------|-------------|
| T-05 | Medium — enumeration possible | Security team | Sprint +1 |
| T-16 | Medium — cold-start trace gap | Platform team | Sprint +2 |
| T-24 | Medium — volumetric DDoS without Shield Advanced | Architecture board | Q3 |
| T-30 | Medium — supply-chain RCE | DevSecOps team | Ongoing |
| T-33 | Medium — dependency confusion without CodeArtifact | DevSecOps team | Sprint +1 |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-07-10 | Auto-generated | Initial release |

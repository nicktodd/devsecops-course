# ESA Mission Registry — STRIDE Demo

A serverless REST API for tracking European Space Agency missions, satellites,
and launches. This project is the **infrastructure artefact** for the STRIDE
threat modelling exercise.

---

## Architecture

```
                      ┌──────────────────────────────────────────────┐
  Client              │              AWS Cloud                        │
    │                 │                                               │
    │  HTTPS + JWT    │  ┌──────────┐    ┌─────────────────────┐     │
    ├────────────────►│  │  API GW  │───►│  Cognito Authorizer  │     │
    │                 │  │(Regional)│    └─────────────────────┘     │
    │                 │  └────┬─────┘             │ verified claims   │
    │                 │       │                   ▼                   │
    │                 │  ┌────▼────────────────────────────────────┐  │
    │                 │  │          Lambda Functions               │  │
    │                 │  │  missions.py │ satellites.py │launches.py│  │
    │                 │  └────┬─────────────────────────────────────┘ │
    │                 │       │ least-privilege IAM role              │
    │                 │  ┌────▼────────────────────────────┐         │
    │                 │  │  DynamoDB (encrypted, PITR on)  │         │
    │                 │  │  missions | satellites | launches│         │
    │                 │  └─────────────────────────────────┘         │
    │                 │                                               │
    │                 │  CloudWatch Logs (90-day retention)           │
    │                 │  X-Ray tracing                                │
    └─────────────────┴───────────────────────────────────────────────┘
```

---

## STRIDE Mitigations Summary

| Threat | Where | Mitigation |
|---|---|---|
| **Spoofing** | API | Cognito User Pool with SRP auth, MFA, short-lived JWTs, email verification |
| **Tampering** | Lambda | Input validation on every write; DynamoDB PITR; HTTPS enforced |
| **Repudiation** | API GW + Lambda | Structured access logs, CloudWatch logs with caller email, X-Ray traces |
| **Information Disclosure** | DynamoDB, S3, API | Encryption at rest (SSE), HTTPS only, security response headers, no body tracing |
| **Denial of Service** | API GW | Per-method throttling (20 rps / 50 burst); pagination enforced in handlers |
| **Elevation of Privilege** | Lambda | Group-based RBAC (`admin` write, `analyst` read-only); least-privilege IAM role |

---

## Project Structure

```
demos/stride/
├── template.yaml          # SAM template — Cognito, API GW, Lambda, DynamoDB
├── pipeline.yaml          # CloudFormation — CodeBuild project + IAM + S3
├── buildspec.yml          # CodeBuild build spec (test → scan → build → deploy)
├── app/
│   ├── requirements.txt   # Runtime dependencies
│   └── src/
│       ├── missions.py    # /missions Lambda handler
│       ├── satellites.py  # /satellites Lambda handler
│       └── launches.py    # /launches Lambda handler
└── tests/
    ├── requirements-test.txt
    └── test_handlers.py   # Unit tests (moto mocks for DynamoDB)
```

---

## API Endpoints

All endpoints require a valid Cognito JWT in the `Authorization` header.

| Method | Path | Roles | Description |
|---|---|---|---|
| GET | `/missions` | all | List missions (paginated) |
| GET | `/missions/{missionId}` | all | Get mission by ID |
| POST | `/missions` | admin | Create a mission |
| PUT | `/missions/{missionId}` | admin | Update a mission |
| DELETE | `/missions/{missionId}` | admin | Delete a mission |
| GET | `/satellites` | all | List satellites (paginated) |
| GET | `/satellites/{satelliteId}` | all | Get satellite by ID |
| POST | `/satellites` | admin | Create a satellite |
| GET | `/launches` | all | List launches (paginated) |
| GET | `/launches/{launchId}` | all | Get launch by ID |
| POST | `/launches` | admin | Create a launch |

---

## Deployment

### Prerequisites
- AWS CLI configured with appropriate permissions
- AWS SAM CLI installed (`pip install aws-sam-cli`)
- Python 3.11

### Deploy the pipeline (once)

```powershell
aws cloudformation deploy `
  --template-file demos/stride/pipeline.yaml `
  --stack-name esa-mission-registry-pipeline `
  --capabilities CAPABILITY_NAMED_IAM `
  --parameter-overrides `
      Environment=dev `
      GitHubOwner=nicktodd `
      GitHubRepo=devsecops-course `
      GitHubBranch=main `
      GitHubConnectionArn=<codestar-connection-arn> `
      DeployRegion=eu-west-1
```

### Manual SAM deploy

```bash
cd demos/stride
sam build
sam deploy --guided
```

### Run tests locally

```bash
cd demos/stride
pip install -r tests/requirements-test.txt -r app/requirements.txt
pytest tests/ -v --cov=app/src
```

### Run security scans locally

```bash
# SAST
bandit -r app/src/ -ll

# Dependency vulnerabilities
pip-audit -r app/requirements.txt
```

---

## Obtaining a JWT for manual testing

```powershell
# 1. Authenticate
aws cognito-idp initiate-auth `
  --auth-flow USER_SRP_AUTH `
  --client-id <UserPoolClientId> `
  --auth-parameters USERNAME=you@example.com,PASSWORD=YourPassword1!

# 2. Use the IdToken in requests
curl -H "Authorization: <IdToken>" `
  https://<api-id>.execute-api.eu-west-1.amazonaws.com/dev/missions
```

# STRIDE Analysis — 01: System Model

## Level 0 — Context Diagram

A high-level view showing the system as a single process and its external actors.

```mermaid
flowchart LR
    classDef actor fill:#dae8fc,stroke:#6c8ebf
    classDef system fill:#d5e8d4,stroke:#82b366
    classDef external fill:#fff2cc,stroke:#d6b656
    classDef datastore fill:#f8cecc,stroke:#b85450

    User(["Analyst / Admin\nUser"]):::actor
    DevOps(["Developer /\nCodeBuild Pipeline"]):::actor

    subgraph Boundary["── AWS Account Boundary ──"]
        API["ESA Mission\nRegistry API"]:::system
        DB[("Mission Data\nDynamoDB")]:::datastore
        Logs[("Audit Logs\nCloudWatch")]:::datastore
        Artifacts[("Build Artefacts\nS3")]:::datastore
    end

    GitHub(["GitHub\nRepository"]):::external

    User -->|"HTTPS + JWT"| API
    API -->|"Read / Write"| DB
    API -->|"Access logs"| Logs
    DevOps -->|"git push"| GitHub
    GitHub -->|"Source code"| DevOps
    DevOps -->|"sam deploy"| API
    DevOps -->|"Build artefacts"| Artifacts
```

---

## Level 1 — Data Flow Diagram

An expanded view showing internal components, data flows, and where authentication occurs.

```mermaid
flowchart TD
    classDef actor fill:#dae8fc,stroke:#6c8ebf
    classDef process fill:#d5e8d4,stroke:#82b366
    classDef datastore fill:#f8cecc,stroke:#b85450
    classDef external fill:#fff2cc,stroke:#d6b656
    classDef boundary fill:none,stroke:#666,stroke-dasharray:6 3

    User(["User\n(Browser / CLI)"]):::actor
    CB(["CodeBuild\nPipeline"]):::actor
    GitHub(["GitHub"]):::external

    subgraph AWS["AWS Cloud (eu-west-1)"]

        subgraph APILayer["API Layer"]
            APIGW["API Gateway\n(Regional REST)"]:::process
            Cognito["Cognito\nUser Pool"]:::process
        end

        subgraph ComputeLayer["Compute Layer"]
            MissionsLambda["missions.py\nLambda"]:::process
            SatsLambda["satellites.py\nLambda"]:::process
            LaunchesLambda["launches.py\nLambda"]:::process
        end

        subgraph DataLayer["Data Layer"]
            MissionsDB[("esa-missions\nDynamoDB")]:::datastore
            SatsDB[("esa-satellites\nDynamoDB")]:::datastore
            LaunchesDB[("esa-launches\nDynamoDB")]:::datastore
        end

        subgraph ObservabilityLayer["Observability"]
            CWLogs[("CloudWatch\nLogs")]:::datastore
            XRay["X-Ray\nTraces"]:::process
        end

        subgraph CICDLayer["CI/CD"]
            S3[("S3 Artifact\nBucket")]:::datastore
        end

        IAMRole["Lambda IAM Role\n(least privilege)"]:::process
    end

    User -->|"1. HTTPS request\n+ Bearer token"| APIGW
    APIGW -->|"2. Validate JWT"| Cognito
    Cognito -->|"3. Return claims\n(email, groups)"| APIGW
    APIGW -->|"4. Invoke + inject claims"| MissionsLambda
    APIGW -->|"4. Invoke + inject claims"| SatsLambda
    APIGW -->|"4. Invoke + inject claims"| LaunchesLambda
    MissionsLambda -->|"5. Assume"| IAMRole
    SatsLambda -->|"5. Assume"| IAMRole
    LaunchesLambda -->|"5. Assume"| IAMRole
    IAMRole -->|"6. DynamoDB CRUD"| MissionsDB
    IAMRole -->|"6. DynamoDB CRUD"| SatsDB
    IAMRole -->|"6. DynamoDB CRUD"| LaunchesDB
    APIGW -->|"7. Structured access log"| CWLogs
    MissionsLambda -->|"7. Application log"| CWLogs
    MissionsLambda -.->|"Trace"| XRay
    GitHub -->|"8. Source pull"| CB
    CB -->|"9. sam package"| S3
    CB -->|"10. sam deploy"| MissionsLambda
    CB -->|"10. sam deploy"| SatsLambda
    CB -->|"10. sam deploy"| LaunchesLambda
```

---

## Component Descriptions

| Component | Technology | Purpose |
|---|---|---|
| API Gateway | AWS REST API (Regional) | TLS termination, request routing, Cognito authorizer, throttling |
| Cognito User Pool | AWS Cognito | User authentication, JWT issuance, group-based RBAC |
| missions.py | Python 3.11 Lambda | CRUD for mission records; enforces admin-only writes |
| satellites.py | Python 3.11 Lambda | CRUD for satellite records |
| launches.py | Python 3.11 Lambda | CRUD for launch records |
| DynamoDB (×3) | AWS DynamoDB on-demand | Persistent storage; SSE enabled; PITR enabled |
| IAM Role | AWS IAM | Least-privilege role: only DynamoDB CRUD on named tables |
| CloudWatch Logs | AWS CloudWatch | API access logs + Lambda application logs; 90-day retention |
| X-Ray | AWS X-Ray | Distributed tracing for non-repudiation and performance |
| CodeBuild | AWS CodeBuild | CI/CD: test → SAST → package → deploy |
| S3 Artifact Bucket | AWS S3 | Encrypted artefact storage; public access blocked |

---

## Key Data Flows

| Flow ID | From | To | Data | Protocol |
|---|---|---|---|---|
| DF-01 | User | API Gateway | HTTP request + JWT | HTTPS |
| DF-02 | API Gateway | Cognito | JWT | Internal AWS |
| DF-03 | Cognito | API Gateway | Claims (email, groups) | Internal AWS |
| DF-04 | API Gateway | Lambda | Event + injected claims | Internal AWS |
| DF-05 | Lambda | DynamoDB | Mission/Satellite/Launch records | Internal AWS |
| DF-06 | API Gateway | CloudWatch | Access log entries | Internal AWS |
| DF-07 | Lambda | CloudWatch | Application logs | Internal AWS |
| DF-08 | CodeBuild | S3 | Packaged SAM template + code | Internal AWS |
| DF-09 | CodeBuild | Lambda | Deployed function code | Internal AWS |
| DF-10 | GitHub | CodeBuild | Source code via CodeConnections | HTTPS |

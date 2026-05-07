# Course Prerequisites

---

## Part 1 — Prerequisites to Complete the Labs

The lab exercises are discussion, analysis, and written-deliverable tasks. The tooling requirements are minimal.

### What you need

| Requirement | Notes |
|---|---|
| **VS Code** (any recent stable version) | Used in Lab 06 to author and preview Mermaid diagrams |
| **Markdown Preview Mermaid Support** VS Code extension | Install from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid); needed to render architecture diagrams in Lab 06 |
| **Git** | To clone the course repository and commit your lab answers |
| **Course repository cloned locally** | All log files, source files, and documentation referenced in labs must be accessible on your machine |
| **Terminal** (`bash`, `zsh`, or PowerShell) | Lab 07 uses `grep` (Linux/macOS) or `Select-String` (PowerShell) to query log files |
| **Web browser** | Lab 08 uses a public read-only SonarCloud dashboard — no account or login required |

### Lab-by-Lab Summary

| Lab | What you do | Tools needed |
|---|---|---|
| **Lab 04** — Secrets & Identity | Group discussion exercise | None |
| **Lab 05** — Cloud & Kubernetes Security | Group scenario analysis | None |
| **Lab 06** — STRIDE Threat Modelling | Write a threat model using Mermaid diagrams | VS Code, Mermaid extension, Git |
| **Lab 07** — Detection Engineering | Analyse structured log files, write detection rules | Terminal (`grep` / PowerShell), Git |
| **Lab 08** — Vulnerability Scanning / SAST | Review a live SonarCloud scan and source files | Web browser, local repo clone |
| **Lab 09** — Incident Response | Tabletop CI/CD supply chain scenario, written answers | Text editor, Git |

### Lab Prerequisites Checklist

- [ ] VS Code installed
- [ ] Markdown Preview Mermaid Support extension installed in VS Code
- [ ] Git installed (`git --version`)
- [ ] Course repository cloned to your machine
- [ ] Terminal available with `grep` (Linux/macOS) or PowerShell (Windows)
- [ ] Web browser (for Lab 08)

---

## Part 2 — Prerequisites to Run the Demos

> **Note for students:** You do not need to run the demos yourself. The instructor will run these live. This section is provided for reference — for example if you want to recreate a demo in your own environment after the course.

### Programming Languages & Runtimes

| Tool | Version | Used In |
|---|---|---|
| Python | **3.11** or **3.12** | OWASP demos, Secure Coding demos, STRIDE app |
| Java JDK | **17+** (covers all requirements) | Secrets Manager demo, OWASP A06/A07, Secure Coding deserialization demo |
| GCC or Clang | Any modern | Secure Coding C/memory-safety demo |

> **Windows users:** install GCC/Clang via [WSL 2](https://learn.microsoft.com/en-us/windows/wsl/) or [MSYS2](https://www.msys2.org/).

### Build Tools

| Tool | Version | Used In |
|---|---|---|
| Apache Maven | **3.6+** | Secrets Manager demo, OWASP A06 (Dependency-Check) |
| pip | Latest | All Python demos |
| make | Any | C memory-safety demo |

### Docker

| Tool | Notes |
|---|---|
| Docker Engine | Must have access to the Docker socket |
| Docker Compose v2 | Bundled with Docker Desktop; verify with `docker compose version` |

At least **8 GB RAM** is recommended so that Clair + PostgreSQL can run alongside other containers.

### AWS

An active AWS account with permissions to create and manage:

| Service |
|---|
| IAM (roles, policies) |
| CloudFormation |
| S3 |
| Secrets Manager |
| Lambda (Python 3.11 runtime) |
| API Gateway (Regional) |
| Cognito User Pools |
| DynamoDB |
| CloudWatch Logs / X-Ray |
| CodeBuild / CodePipeline |
| CodeStar Connections (to GitHub) |
| SSM Parameter Store |
| EC2 / VPC / Security Groups |

Default deployment region used in demos: **eu-west-1**.

**AWS CLI** — install and configure with `aws configure`

**AWS SAM CLI** — `pip install aws-sam-cli`

### Python Security Packages

```bash
pip install bandit pip-audit safety pip-tools
```

### CI/CD Platform Accounts

| Platform | Requirement |
|---|---|
| **Bitbucket** | Free account + repository (container image scan pipeline) |
| **GitHub** | Free account (CodeBuild/CodePipeline via CodeStar Connections) |
| **Jenkins** | Local install or Docker image (OWASP A06 & A08 Jenkinsfile demos) |

### External API Keys

| Service | Registration | Used In |
|---|---|---|
| **NVD API key** (free) | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) | OWASP A06 Jenkins Dependency-Check plugin |

### Command-Line Utilities

`curl`, `grep`, `sha256sum` (or `certutil -hashfile` on Windows), `javac` / `java`, `bash` / `zsh`

### Disk & Memory

| Requirement | Detail |
|---|---|
| **≥8 GB RAM** | Docker containers (Clair + PostgreSQL) |
| **≥5 GB free disk** | NVD CVE database, Docker images, Maven/pip caches |
| **Internet access** | Maven Central, PyPI, Docker Hub, Quay.io, GitHub releases, NVD |

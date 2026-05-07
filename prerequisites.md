# Student Machine Prerequisites

This document lists everything you need installed and configured before attending the course. Not every prerequisite is needed for every module — the tables below indicate which demos/labs each item supports.

---

## 1. Programming Languages & Runtimes

| Tool | Version | Used In |
|---|---|---|
| Python | **3.11** or **3.12** | OWASP demos, Secure Coding demos, STRIDE app |
| Java JDK | **17+** (covers all requirements) | Secrets Manager demo, OWASP A06/A07, Secure Coding deserialization demo |
| GCC or Clang | Any modern | Secure Coding C/memory-safety demo |

> **Windows users:** install GCC/Clang via [WSL 2](https://learn.microsoft.com/en-us/windows/wsl/) or [MSYS2](https://www.msys2.org/).

---

## 2. Build Tools

| Tool | Version | Used In |
|---|---|---|
| Apache Maven | **3.6+** | Secrets Manager demo, OWASP A06 (Dependency-Check) |
| pip | Latest | All Python demos |
| make | Any | C memory-safety demo |

---

## 3. Docker

| Tool | Notes |
|---|---|
| Docker Engine | Must have access to the Docker socket |
| Docker Compose v2 | Bundled with Docker Desktop; verify with `docker compose version` |

Docker is used for the container image scanning demo (Clair), the Bitbucket pipeline, and several OWASP demos. **At least 8 GB RAM** is recommended for the machine so that Clair + PostgreSQL can run comfortably alongside other containers.

---

## 4. AWS

### AWS Account
You need an active AWS account with permissions to create and manage:

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
| CloudWatch Logs |
| X-Ray |
| CodeBuild / CodePipeline |
| CodeStar Connections (to GitHub) |
| SSM Parameter Store |
| EC2 / VPC / Security Groups |

> The default deployment region used in demos is **eu-west-1**. You can change this, but make sure your account has the services available in your chosen region.

### AWS CLI
Install and configure the AWS CLI with credentials for your account:

```bash
aws configure
```

### AWS SAM CLI
Required for the STRIDE serverless demo:

```bash
pip install aws-sam-cli
```

---

## 5. Python Packages (global or per-venv)

Install these globally or in a virtual environment before the course:

```bash
pip install bandit pip-audit safety pip-tools
```

| Package | Purpose |
|---|---|
| `bandit` | Python static analysis (SAST) |
| `pip-audit` | Python dependency CVE scanning |
| `safety` | Python dependency scanning |
| `pip-tools` | Dependency pinning and lock files |

Demo-specific packages (`flask`, `pyjwt`, `requests`, etc.) are installed per-demo as part of the exercise instructions.

---

## 6. Security Scanning Tools

| Tool | Install | Purpose |
|---|---|---|
| Bandit | `pip install bandit` | Python SAST |
| pip-audit | `pip install pip-audit` | Python dependency CVE scanning |
| safety | `pip install safety` | Python dependency scanning |
| clairctl v4.7.3 | Auto-downloaded by `demos/dockerimages/scan.sh` | CLI for submitting images to Clair |

---

## 7. CI/CD Platforms & Accounts

| Platform | Requirement | Used In |
|---|---|---|
| **Bitbucket** | Free account + a repository | Docker image scan pipeline lab |
| **GitHub** | Free account | CodeBuild/CodePipeline via CodeStar Connections (STRIDE lab) |
| **Jenkins** | Local install or Docker image | OWASP A06 & A08 Jenkinsfile demos |

> Jenkins is only needed if you want to run the Jenkinsfile demos locally. A Docker-based Jenkins instance is sufficient.

---

## 8. External API Keys & Registrations

| Service | How to Register | Used In |
|---|---|---|
| **NVD API key** (free) | [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) | OWASP A06 Jenkins OWASP Dependency-Check plugin |

> Without an NVD API key the Dependency-Check plugin falls back to unauthenticated requests, which are heavily rate-limited and can cause the demo to time out.

---

## 9. VS Code

Install [Visual Studio Code](https://code.visualstudio.com/) (any recent stable version).

### Required Extensions

| Extension | Purpose |
|---|---|
| [Markdown Preview Mermaid Support](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) | Render Mermaid diagrams in the STRIDE threat-modelling lab |

---

## 10. Command-Line Utilities

These standard tools must be available in your terminal:

| Tool | Notes |
|---|---|
| `bash` (or `zsh`) | All shell scripts; Windows users should use WSL 2 |
| `curl` | Image scanning scripts, OWASP demo API calls |
| `grep` | Detection Engineering lab (Windows alternative: PowerShell `Select-String`) |
| `sha256sum` | OWASP A08 integrity demo (Windows: `certutil -hashfile`) |
| `javac` / `java` | Java demo compilation |
| `git` | Cloning and working with the course repository |

---

## 11. Disk & Memory

| Requirement | Detail |
|---|---|
| **≥8 GB RAM** | Required to run Docker containers for Clair + PostgreSQL alongside normal workloads |
| **≥5 GB free disk** | NVD CVE database (~300 MB on first run), Docker images, Maven/pip caches |
| **Internet access** | Maven Central, PyPI, Docker Hub, Quay.io, GitHub releases, NVD |

---

## Quick-Start Checklist

Use this list on the day:

- [ ] Python 3.11 or 3.12 installed (`python --version`)
- [ ] Java JDK 17+ installed (`java -version`)
- [ ] Apache Maven 3.6+ installed (`mvn -version`)
- [ ] GCC or Clang installed (`gcc --version` / `clang --version`)
- [ ] Docker Engine + Compose v2 running (`docker compose version`)
- [ ] AWS CLI installed and configured (`aws sts get-caller-identity`)
- [ ] AWS SAM CLI installed (`sam --version`)
- [ ] Bandit, pip-audit, safety, pip-tools installed (`bandit --version`)
- [ ] VS Code installed with Markdown Preview Mermaid Support extension
- [ ] Bitbucket account created
- [ ] GitHub account created
- [ ] NVD API key obtained
- [ ] Git installed (`git --version`)

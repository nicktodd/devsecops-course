# OWASP A08:2021 – Software and Data Integrity Failures

## What Is It?

Software and Data Integrity Failures occur when code and infrastructure pipelines do not verify the integrity of externally sourced software, scripts, or artifacts before using them. Attackers who compromise an upstream dependency, registry, or artifact server can insert malicious code that silently flows into your deployment.

Common patterns include:

- **`curl | bash`** — downloading and immediately executing a remote script with no inspection
- **Mutable Docker tags** (`latest`) — the underlying image can change between pulls with no warning
- **Unverified artifact downloads** — a JAR or binary deployed without checksum validation can be tampered with in transit or at the source

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/Jenkinsfile` | `curl\|bash`, `docker pull maven:latest`, artifact downloaded over HTTP with no checksum |
| `fixed/Jenkinsfile` | HTTPS downloads, SHA-256 verification before execution, Docker image pinned to immutable digest |

## How to Run

### Prerequisites

- A Jenkins instance with the Pipeline and HTML Publisher plugins installed
- Docker available on the Jenkins agent
- `sha256sum` available (standard on Linux; use `certutil -hashfile` on Windows)

### Vulnerable Pipeline

1. Create a new Jenkins Pipeline job
2. Set the pipeline script source to `vulnerable/Jenkinsfile`
3. Run the build

**Observe:** The pipeline does not validate anything it downloads. Substituting a malicious script at `DEPLOY_SCRIPT_URL` would execute without any error.

### Fixed Pipeline

1. Create a new Jenkins Pipeline job
2. Set the pipeline script source to `fixed/Jenkinsfile`
3. Run the build

**Observe a tamper scenario** — modify the expected hash to an incorrect value:

```groovy
DEPLOY_SCRIPT_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
```

Re-run the pipeline. The `Fetch and Verify Deploy Script` stage will fail with:

```
sha256sum: WARNING: 1 computed checksum did NOT match
ERROR: script returned exit code 1
```

The pipeline aborts — the tampered (or wrong) script is never executed.

### Computing a Real Checksum

```bash
# For a script:
sha256sum deploy.sh

# For a JAR:
sha256sum app.jar

# For a Docker image digest:
docker inspect --format='{{index .RepoDigests 0}}' maven:3.9.6-eclipse-temurin-17
```

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Script download transport | HTTP | HTTPS |
| Script execution | Immediate (`curl \| bash`) | Download → verify SHA-256 → execute |
| Docker image pinning | Mutable `latest` tag | Immutable `sha256:` digest |
| Artifact transport | HTTP | HTTPS |
| Artifact verification | None | SHA-256 checksum before execution |
| Failure alerting | None | Post-failure notification block |

## References

- [OWASP A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Docker Content Trust](https://docs.docker.com/engine/security/trust/)
- [SLSA Framework — Supply Chain Levels for Software Artifacts](https://slsa.dev/)

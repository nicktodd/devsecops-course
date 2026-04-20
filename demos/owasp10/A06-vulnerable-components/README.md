# OWASP A06:2021 – Vulnerable and Outdated Components

## What Is It?

Vulnerable and Outdated Components occur when software uses libraries, frameworks, or other dependencies that contain known security vulnerabilities. Once a CVE is published, attackers immediately search for applications using the affected version. This category covers:

- Using dependency versions with known CVEs
- No automated process to detect new vulnerabilities in existing dependencies
- No gate in the CI/CD pipeline that prevents a vulnerable build from deploying

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/pom.xml` | Maven POM with three critical CVEs: Log4Shell, Spring4Shell, Jackson deserialization RCE |
| `vulnerable/Jenkinsfile` | Pipeline with no scanning — vulnerable build ships to production |
| `fixed/pom.xml` | Updated dependency versions + OWASP Dependency-Check plugin configured to break the build on CVSS >= 7 |
| `fixed/Jenkinsfile` | Pipeline with a mandatory scan gate before the build stage |

## CVEs in the Vulnerable POM

| Library | Version | CVE | CVSS | Description |
|---|---|---|---|---|
| `log4j-core` | 2.14.1 | CVE-2021-44228 (Log4Shell) | 10.0 CRITICAL | RCE via JNDI lookup in any logged string |
| `spring-webmvc` | 5.3.0 | CVE-2022-22965 (Spring4Shell) | 9.8 CRITICAL | RCE via Spring MVC data binding on JDK 9+ |
| `jackson-databind` | 2.9.8 | CVE-2019-14540 | 9.8 CRITICAL | RCE via unsafe JSON deserialization |

## How to Run

### Prerequisites

- Java 11+, Maven 3.6+
- Jenkins instance (for pipeline demos)
- Internet access for Maven Central and the NVD CVE database

### Run the Dependency Scan Manually

**Vulnerable — scan will find CVEs but build proceeds anyway (no scan configured):**

```bash
cd vulnerable
mvn clean package -DskipTests
# Builds successfully with no CVE warnings
```

**Fixed — scan runs automatically and fails the build on CVSS >= 7:**

```bash
cd fixed
mvn dependency-check:check
# Downloads NVD CVE database (~300 MB first run, cached after)
# Fails with: "One or more dependencies were identified with known vulnerabilities"
# Open target/dependency-check-report.html to view the findings
```

**Run the full build (scan + compile + test):**

```bash
cd fixed
mvn clean verify
# The verify lifecycle includes the dependency-check:check goal
# Build will fail if any High or Critical CVE is found
```

### Jenkins Pipeline

Load the `Jenkinsfile` from each directory as a pipeline job in Jenkins.

**Vulnerable pipeline:** completes all stages with no CVE warnings.

**Fixed pipeline:**
1. Add an NVD API key to Jenkins Credentials with ID `nvd-api-key` (free registration at https://nvd.nist.gov/developers/request-an-api-key)
2. The `Dependency Security Scan` stage runs first — if it detects any CVE with CVSS >= 7, the pipeline aborts and publishes an HTML report with the findings

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Log4j version | 2.14.1 (Log4Shell) | 2.17.1 (patched) |
| Spring version | 5.3.0 (Spring4Shell) | 5.3.20 (patched) |
| Jackson version | 2.9.8 (deserialization RCE) | 2.13.4 (patched) |
| CVE scanning | None | OWASP Dependency-Check (break on CVSS >= 7) |
| Pipeline gate | None | Scan must pass before build proceeds |
| Artifact integrity | None | SHA-256 checksum verified before deploy |

## References

- [OWASP A06:2021 – Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [NVD CVE Database](https://nvd.nist.gov/)

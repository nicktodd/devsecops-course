# Solution Guide: OWASP Top 10 – Identifying Risks in Real Systems

## Purpose

This guide provides **reference answers and reasoning** for the OWASP Top 10 lab.

The goal is not just correct answers, but understanding:

- how to recognise patterns
- how to reason about root cause
- how to prioritise risk in real systems

---

## Part 1 – Identify the Risk Category

### Observation 1

A user can change the `userId` parameter in an API request and retrieve another user’s data.

- OWASP Category:  
  Broken Access Control

- Root Cause:  
  Missing object-level authorization checks (server trusts user-supplied identifiers)

- Impact:  
  Unauthorized data access, possible full exposure of user dataset

---

### Observation 2

Application logs contain full JWT tokens and API keys in plaintext.

- OWASP Category:  
  Security Logging and Monitoring Failures *(primary)*  
  Also relates to Cryptographic Failures

- Root Cause:  
  Sensitive data logged without protection or redaction

- Impact:  
  Credential theft, privilege escalation, lateral movement

---

### Observation 3

The application uses an outdated npm package with a known remote execution vulnerability.

- OWASP Category:  
  Vulnerable and Outdated Components

- Root Cause:  
  Lack of dependency management or patching strategy

- Impact:  
  Remote code execution, full system compromise

---

### Observation 4

A build pipeline automatically installs dependencies, including a package that runs scripts on install.

- OWASP Category:  
  Software and Data Integrity Failures

- Root Cause:  
  Blind trust in dependency execution (post-install scripts)

- Impact:  
  Supply chain compromise affecting CI/CD and developers

---

### Observation 5

Login attempts are not rate limited, and sessions remain valid for several days.

- OWASP Category:  
  Identification and Authentication Failures

- Root Cause:  
  Weak authentication controls and poor session lifecycle management

- Impact:  
  Account takeover, brute-force attacks, session hijacking

---

### Observation 6

An internal API allows users to provide a URL which the server fetches without validation.

- OWASP Category:  
  Server-Side Request Forgery (SSRF)

- Root Cause:  
  Unvalidated user-controlled requests to external/internal resources

- Impact:  
  Access to internal services, metadata endpoints, credential theft

---

### Observation 7

The application uses custom encryption logic written by developers instead of a standard library.

- OWASP Category:  
  Cryptographic Failures

- Root Cause:  
  Improper cryptographic design and implementation

- Impact:  
  Data exposure, broken encryption guarantees, compliance violations

---

### Observation 8

A debug endpoint is accessible in production and exposes environment configuration.

- OWASP Category:  
  Security Misconfiguration

- Root Cause:  
  Insecure default / debug configuration left enabled

- Impact:  
  Exposure of secrets, internal system details, attack surface expansion

---

## Part 2 – Design vs Code vs Configuration

### Suggested Classification

Observation 1:  

- Coding issue (missing authorization checks)

Observation 2:

- Coding issue (logging design flaw)

Observation 3:  

- Process / configuration issue (dependency management)

Observation 4:

- Design issue (trust model in CI/CD pipeline)

Observation 5:  

- Design issue (authentication and session policy)

Observation 6:  

- Coding issue (lack of validation)

Observation 7:  

- Design issue (crypto approach chosen incorrectly)

Observation 8:  

- Configuration issue (production hardening failure)

---

## Part 3 – Prioritisation Exercise

### Suggested Top 3

1. Observation 3 – Vulnerable dependency  
   - High exploitability (known CVE)  
   - Potential remote code execution  

2. Observation 1 – Broken access control  
   - Direct data exposure  
   - Common and easily exploitable  

3. Observation 4 – Pipeline dependency execution  
   - High blast radius  
   - Can impact multiple systems and releases  

---

### Reasoning Approach

Prioritisation should consider:

- Exploitability: how easy is it to abuse?
- Impact: what is the worst-case outcome?
- Blast radius: how many systems are affected?
- Exposure: is this externally reachable?

---

## Part 4 – Mitigation Examples

### Observation 1

Mitigation:

- Enforce server-side authorization checks on every request
- Implement deny-by-default access model
- Use centralized authorization logic

---

### Observation 4

Mitigation:

- Restrict execution of dependency scripts
- Use dependency pinning and lockfiles
- Introduce artifact verification or allowlists

---

### Observation 5

Mitigation:

- Add rate limiting and lockout controls
- Use short-lived session tokens
- Implement secure session rotation

---

## Part 5 – Pattern Recognition

### Common Patterns Observed

- Trusting client input  
- Implicit trust between systems  
- Lack of validation  
- Overprivileged access  
- Weak defaults  

---

## Part 6 – Reflection Guidance

### Typical Insights

Participants often discover:

- Security issues are often simple but systemic
- Most problems come from trust assumptions, not syntax
- CI/CD and dependencies increase risk significantly

---

## Key Takeaways

- OWASP Top 10 is a risk framework, not a checklist  
- Many issues are:
  - design problems
  - trust failures
  - integration gaps  
- The most dangerous vulnerabilities:
  - are easy to exploit
  - affect multiple systems
  - hide inside normal behaviour  

---

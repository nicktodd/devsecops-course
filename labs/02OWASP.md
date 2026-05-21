# Lab: OWASP Top 10 – Identifying Risks in Real Systems

## Purpose

This lab helps you move from **memorising OWASP categories** to actually **recognising risk patterns in real systems**.

You will:

- identify vulnerabilities in realistic scenarios
- map issues to OWASP Top 10 categories
- think about root causes (design vs code vs configuration)
- suggest practical mitigations

---

## Scenario Overview

You are reviewing a modern web application with the following characteristics:

- React frontend
- REST API backend
- Uses JWT authentication
- Runs in a cloud environment
- Built and deployed via CI/CD pipeline
- Uses third-party dependencies from npm

You are given a set of observations from a recent review.

---

## Part 1 – Identify the Risk Category

For each observation below:

1. Identify the **most relevant OWASP category**
2. Explain the **root cause**
3. Describe the **impact**

---

### Observation 1

A user can change the `userId` parameter in an API request and retrieve another user’s data.

- OWASP Category:
- Root Cause:
- Impact:

---

### Observation 2

Application logs contain full JWT tokens and API keys in plaintext.

- OWASP Category:
- Root Cause:
- Impact:

---

### Observation 3

The application uses an outdated npm package with a known remote execution vulnerability.

- OWASP Category:
- Root Cause:
- Impact:

---

### Observation 4

A build pipeline automatically installs dependencies, including a package that runs scripts on install.

- OWASP Category:
- Root Cause:
- Impact:

---

### Observation 5

Login attempts are not rate limited, and sessions remain valid for several days.

- OWASP Category:
- Root Cause:
- Impact:

---

### Observation 6

An internal API allows users to provide a URL which the server fetches without validation.

- OWASP Category:
- Root Cause:
- Impact:

---

### Observation 7

The application uses custom encryption logic written by developers instead of a standard library.

- OWASP Category:
- Root Cause:
- Impact:

---

### Observation 8

A debug endpoint is accessible in production and exposes environment configuration.

- OWASP Category:
- Root Cause:
- Impact:

---

## Part 2 – Design vs Code vs Configuration

For each of the observations above, classify the issue:

- Design issue (architectural problem)
- Coding issue (implementation flaw)
- Configuration issue (environment / deployment problem)

Example:

Observation 1:
- Type:

---

## Part 3 – Prioritisation Exercise

Assume you can only fix **three issues this sprint**.

Choose:
- Issue 1:
- Issue 2:
- Issue 3:

Explain your prioritisation based on:
- exploitability
- impact
- likelihood
- blast radius

---

## Part 4 – Mitigation Thinking

Select two observations and propose concrete mitigations.

### Example format

Observation:
Mitigation:

---

## Part 5 – Reflection

### A. Pattern Recognition

Which of the following patterns did you see most frequently?

- Trusting client input
- Implicit trust between systems
- Overprivileged access
- Lack of validation
- Weak defaults

---

### B. Key Insight

What surprised you most about these risks?

---

### C. Real-System Mapping

Think about your own systems.

Which OWASP category are you most concerned about?

Why?

---

## Key Takeaways

- OWASP Top 10 is a **risk framework**, not a checklist
- Most issues come from:
  - trust assumptions
  - design decisions
  - integration between systems
- Many vulnerabilities are simple in isolation, but **high impact at scale**
- Secure systems require:
  - validation
  - least privilege
  - defence-in-depth

---

## Optional Discussion (Group)

Discuss:

- Which vulnerabilities are easiest to exploit?
- Which are hardest to detect?
- Which would cause the biggest real-world incident?

---


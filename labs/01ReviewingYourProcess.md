# Exercise: Mapping Your Software Supply Chain Attack Surface

## Purpose

Modern attacks rarely target production systems first.  
Instead, attackers exploit **trust relationships across the software delivery lifecycle**.

This exercise helps you:

- understand how real attacks propagate
- identify attack paths in your own environment
- recognise where implicit trust exists
- start thinking in terms of defence-in-depth and zero trust

---

## Scenario Introduction

Consider the following real pattern (based on supply chain attacks):

A trusted dependency introduces malicious behaviour through an automated process.  
Build pipelines consume the dependency without validation, and the compromise spreads to downstream systems.

---

## Part 1 – Map Your Delivery Lifecycle

Choose a system you are familiar with.

### A. Identify the key stages

Write down your software delivery flow using this structure:

Planning → Coding → Build → Test → Package → Release → Deploy → Operate

Now map your actual implementation:

- Source control system:
- CI/CD platform:
- Artifact storage:
- Deployment environment:
- Cloud platform:

---

### B. Identify key assets at each stage

For each stage, list the critical assets.

Stage: Source  
Key assets:

Stage: Build  
Key assets:

Stage: Test  
Key assets:

Stage: Release  
Key assets:

Stage: Deployment  
Key assets:

Stage: Runtime  
Key assets:

Examples:

- Source code
- Secrets and tokens
- Build definitions
- Artifact binaries
- Signing keys

---

## Part 2 – Identify Trust Boundaries

A trust boundary exists wherever control or data moves between systems or users.

### A. Mark high-risk boundaries

For your system, identify where trust is implicitly assumed:

- Developer → Source control
- Source control → CI/CD runner
- CI/CD runner → Cloud platform
- Artifact registry → Production

Question:  
Which boundary would cause the most damage if compromised?

---

## Part 3 – Simulate an Attack Path

### A. Choose a starting point

Select one likely entry point:

- Compromised developer account  
- Malicious dependency  
- Stolen CI/CD token  
- Compromised runner  
- Third-party integration  

---

### B. Walk the attack path

Describe how the attack would spread:

1. Initial compromise:
2. What the attacker gains access to:
3. Next system or boundary crossed:
4. Final impact:

Prompt:  
How could this attack reach production without being detected?

---

## Part 4 – Identify Weaknesses

Based on your attack path, highlight weaknesses:

- Implicit trust in dependencies  
- Lack of artifact verification  
- Overprivileged service accounts  
- Shared CI/CD infrastructure  
- Weak branch protection  
- Poor logging or observability  

---

## Part 5 – Defence-in-Depth Thinking

### A. Add protections at multiple layers

For your attack path, identify controls at each stage.

Source stage controls:

Build stage controls:

Artifact stage controls:

Deployment stage controls:

Runtime stage controls:

Examples:

- Signed commits
- Dependency pinning
- Isolated runners
- Artifact signing
- Deployment approvals

---

### B. Apply Zero Trust Principles

Answer the following:

- Which systems currently assume implicit trust?
- Where should access be reduced to least privilege?
- Which identities (human or machine) have more access than needed?

---

## Part 6 – Reflection

### A. Biggest insight

What part of your delivery pipeline is more exposed than you expected?

---

### B. Most critical gap

If an attack happened tomorrow, where would detection or containment be hardest?

---

### C. One improvement

What is one control you could realistically introduce in the next 30–60 days?

Examples:

- Lock dependency versions
- Limit CI/CD token scope
- Introduce artifact verification
- Improve logging retention

---

## Key Takeaway

Modern attacks do not break systems.  
They abuse trust between them.

Understanding how code, credentials, and artifacts move —  
and where trust is assumed — is the foundation of a secure DevSecOps mindset.

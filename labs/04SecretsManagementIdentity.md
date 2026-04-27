# Group Exercise: Identity and Secrets Risk Reflection

This is a collaborative reflective exercise designed to help you reason about identity, tokens, and secrets in a real environment rather than an idealised one.

This is not an audit. There are no right or wrong answers.
The aim is to identify where identity or secrets weaknesses could create unnecessary risk and what single improvement would have the biggest impact.

You will work as a group and then briefly present your conclusions back.

---

## Instructions

Complete this exercise as a group.
Focus on one real system or environment.
Keep discussions practical and honest.
Aim to identify one key weakness and one improvement.

---

## 1. Environment in Scope

Describe the environment or system your group has chosen to focus on.

System or service name:
Environment (for example dev, test, production):
Platforms involved (cloud, on‑prem, SaaS, CI/CD, Kubernetes, etc.):
Why this environment matters:


---

## 2. Key Human Identities

List the most important human identities involved in this environment.

Consider developers, operators, administrators, contractors, or external users.

Questions to discuss:
Who has privileged access?
Are there standing admin roles?
Is production access tightly limited?



---

## 3. Service Accounts, Roles, and Workload Identities

Identify non‑human identities used by this environment.

Examples include CI/CD pipeline identities, deployment roles, application or service accounts, and integration identities.

Questions to discuss:
Are any identities shared across multiple systems?
Are permissions narrowly scoped to what is required?
Are any identities long‑lived or rarely reviewed?



---

## 4. Secrets and Tokens in Use

Identify where secrets or credentials exist today.

Consider CI/CD pipelines, environment variables, application configuration, secret managers or vaults, local files or scripts, and OAuth access or refresh tokens.

Questions to discuss:
Where are secrets injected at runtime?
How long do tokens or credentials remain valid?
Are secrets copied across multiple locations?



---

## 5. Likely Abuse Scenario

As a group, discuss the following.

If a single token, secret, or identity from this environment was compromised, what would an attacker most likely be able to do?

Think about immediate access, lateral movement, persistence, and time to detection.



---

## 6. Weakest Point Identified

Identify one weakness that represents the most significant risk.

Examples might include over‑privileged roles, long‑lived tokens, shared service accounts, difficulty revoking access, or inconsistent controls across platforms.



---

## 7. One Improvement to Prioritise

Agree on one realistic improvement that would reduce identity or secrets‑related risk the most.

Complete the following sentence as a group.

The single change we would prioritise to reduce risk is:



---

## Presentation Back

Be ready to briefly share:
The environment you focused on.
The weakest point you identified.
The one improvement you would prioritise.

---

## Final Reflection

Strong identity and secrets management does not assume compromise will never happen.
It assumes failures will occur and focuses on limiting blast radius, speed of misuse, and time to recovery.
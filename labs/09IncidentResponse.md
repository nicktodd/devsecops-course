# Lab: Incident Response for Engineers – CI/CD Supply Chain Scenario

## Lab Overview

This lab simulates a **realistic CI/CD security incident** and asks you, as an engineer, to respond safely under pressure.

You will not exploit systems or run tools.  
Instead, you will practise **decision‑making**, **containment planning**, and **forensic discipline**—the skills engineers need most during real incidents.

The focus is on:
- preserving evidence
- limiting blast radius
- avoiding irreversible or damaging actions
- setting up learning and resilience improvements after the incident

---

## Scenario Briefing

You are on-call for the **ESA Mission Registry** — the serverless REST API built in the
STRIDE and detection engineering labs.

At 02:10 UTC, security monitoring raises an alert:

- A CI/CD pipeline published a release artifact **outside normal hours**
- The artifact is **unsigned** and **3.5 % larger** than the previous identical build
- A **long‑lived service account token** was used that has not been accessed in 90 days
- Two repositories share the same **self‑hosted runners**
- Automated deployments are configured to promote artifacts immediately after build

No customer impact has yet been confirmed.

> 📂 **Evidence files for this lab**
>
> The following files in the course repository contain the actual log data you will
> work with during this exercise:
>
> | File | Contents |
> |------|----------|
> | `demos/detection/common_attacker_profile.md` | Attacker identity, IPs, and account details |
> | `demos/detection/attack-reconstruction/attack_sequence.jsonl` | Full chronological event log |
> | `demos/detection/cicd-supply-chain/pipeline_suspicious.jsonl` | CI/CD pipeline logs for the compromised build |
> | `demos/detection/cicd-supply-chain/pipeline_gaps.md` | Analysis of what was logged and what was missing |
>
> Open these files alongside the lab. Answers to Part 1C and the timeline exercise in
> Part 7 come directly from this data.

---

## Part 1 – Establish Initial Scope

Answer the following based on the scenario.

### A. Assets to consider

List all assets that may need to be checked during scoping.

- Source control (repositories, branches, pull requests)
- CI/CD pipelines and workflows
- Build runners or agents
- Artifact registries
- Deployment targets
- Secrets and credentials

> **Question:**  
> Which of these assets could expand the incident *blast radius* if compromised?

---

### B. Identify high‑value identifiers

List the **specific identifiers** you would look for to anchor investigation:

- Commit SHAs
- Job IDs / workflow runs
- Artifact IDs or digests
- Token or service account identifiers
- Runner hostnames or instance IDs

> **Question:**  
> Which identifier would you try to obtain *first*, and why?

---

### C. Separate fact from assumption

Open `demos/detection/cicd-supply-chain/pipeline_suspicious.jsonl` and classify
what is logged as fact vs. what must still be assumed:

**Confirmed facts** *(directly visible in the logs)*
-  
-  

**Unconfirmed assumptions** *(not yet evidenced)*
-  
-  

> 💡 Example to get you started — the log records `actor: k.petrov@external-contractor.io`
> as the identity on the pipeline trigger. That is a *confirmed fact*. Whether
> `k.petrov` is the attacker, or whether their account was itself compromised, is an
> *unconfirmed assumption* until corroborated.

> **Rule:**  
> Do not treat assumptions as evidence during containment.

---

## Part 2 – Immediate Containment Planning

Your goal is to **stop attacker activity without destroying evidence**.

### A. Actions you should take immediately

Select actions that are *reversible* and *low risk*:

- [ ] Pause affected pipelines and scheduled jobs
- [ ] Block artifact promotion
- [ ] Disable or restrict the suspicious token
- [ ] Isolate affected runners from the network
- [ ] Snapshot configuration and runner state

> **Question:**  
> Which action reduces risk *fastest* without losing evidence?

---

### B. Actions you should **not** take yet

Identify actions that could damage the investigation if done too early:

- [ ] Restarting runners
- [ ] Deleting build logs
- [ ] Cleaning workspaces
- [ ] Force‑pushing fixes to production branches
- [ ] Rotating *all* secrets at once without order

> **Question:**  
> Which action is most tempting—and most harmful—under pressure?

---

## Part 3 – Forensic Readiness

Before remediation, evidence must be preserved.

### A. Evidence to preserve

The `pipeline_gaps.md` file documents exactly which logs existed and which were absent
during this incident. Review it, then select everything that should be collected *before*
major changes:

- [ ] Source control audit logs
- [ ] CI/CD job logs (successful and failed)
- [ ] Runner telemetry and system logs
- [ ] Artifact registry access logs
- [ ] Cloud IAM and control‑plane logs

> **Question:**  
> `pipeline_gaps.md` lists six pieces of evidence that were *missing*. Which single
> missing log would have been most valuable to the investigation, and why?

---

### B. Evidence handling discipline

Answer the following:

- Where would evidence be stored?
- How would you prevent modification after collection?
- What timestamps or time zones must be preserved exactly?

> **Rule:**  
> Perform analysis on copies or snapshots, not live systems.

---

## Part 4 – Working Safely Under Pressure

Incidents are chaos by default—discipline prevents mistakes.

### A. Proposed actions tabletop

The following six actions have all been proposed by members of the on-call team.
For each one, decide: **take now / defer / do not take**, and assign who must
approve it before it is executed.

| # | Proposed action | Take now / Defer / Do not take | Approver | Reversible? |
|---|-----------------|-------------------------------|----------|-------------|
| 1 | Pause the `esa-mission-registry` pipeline | | | |
| 2 | Delete `build-2042` logs to stop data leaving the system | | | |
| 3 | Disable `k.petrov`'s GitHub and AWS account | | | |
| 4 | Rotate all secrets immediately and simultaneously | | | |
| 5 | Snapshot the runner filesystem before touching anything | | | |
| 6 | Force-push a revert commit to `main` | | | |

> 💡 Refer to `pipeline_suspicious.jsonl` — `build-2042` is the specific build ID
> to contain.

### B. Access control during the incident

Describe how you would handle emergency access:

- Who approves emergency privileges?
- Are credentials short‑lived?
- How are actions recorded?

> **Rule:**  
> No single‑engineer, irreversible changes during an active incident.

---

## Part 5 – Secret Rotation Strategy

Secrets may be compromised even without proof of misuse.

### A. Prioritisation order

Rank which secrets you would rotate **first**:

- Cloud roles
- Artifact publishing credentials
- Deployment service accounts
- Code signing keys
- Application secrets

> **Question:**  
> Why does order matter during rotation?

---

### B. Documentation

For each rotated secret, record:

- When it was disabled
- When it was replaced
- Where dependent systems were updated
- When functionality was verified

---

## Part 6 – Post‑Incident Learning

After containment and recovery, learning must be captured.

### A. Engineering improvements

List **three structural improvements** that would reduce future risk:

-  
-  
-  

Examples:
- Ephemeral runners
- Signed artifacts
- Reduced service account scope
- Better log retention
- Improved alerts

---

### B. Detection and response gaps

Use the actual events in `attack_sequence.jsonl` and `pipeline_suspicious.jsonl`
to answer:

- What was detected early? *(Which events generated a WARN or anomaly flag?)*
- What was delayed or missed? *(Cross-reference `pipeline_gaps.md`)*
- What would you alert on next time? *(Name the specific field or value you would trigger on)*

---

## Part 7 – Timeline Reconstruction

Open `demos/detection/attack-reconstruction/attack_sequence.jsonl` and
`demos/detection/cicd-supply-chain/pipeline_suspicious.jsonl`.

### A. Reconstruct the attack timeline

Place the events below in the correct chronological order by filling in the
timestamp from the log files:

| Timestamp (UTC) | Event |
|-----------------|-------|
| | First authentication failure from `185.220.101.47` |
| | Successful login by `k.petrov` (attempt 15) |
| | Full dataset bulk-downloaded from `/missions` endpoint |
| | `buildspec.yml` modified on `main` |
| | `EXFIL_ENDPOINT` environment variable added to CodeBuild |
| | Pipeline `build-2042` triggered |
| | SAST gate breached but build continued |
| | Outbound connection to `198.51.100.42` during BUILD phase |
| | Deployment to `esa-mission-registry` stack completed |

> 📂 Timestamps are in the log files — no guessing required.

### B. Gap analysis

- How long elapsed between the **first auth failure** and **deployment completion**?
- At what point was the *earliest* opportunity to detect and stop this attack?
- Which log source provided the earliest signal?

### C. What the STRIDE model predicted

In Lab 6 (STRIDE Threat Modelling), threats were identified against the ESA Mission
Registry. Look at your completed STRIDE artefacts (or `demos/stride/stride-documentation/`)
and answer:

- Which STRIDE category covers the credential brute-force?
- Which STRIDE category covers the pipeline definition tampering?
- Were these threats already in the threat register? If so, were the recommended
  mitigations in place?

---

## Key Takeaways

- **The unsigned artifact was the alert trigger** — but the real entry point was
  a brute-forced account 28 minutes earlier. Early signals exist; they must be monitored.
- **The SAST gate was bypassed silently** — detection is useless if it does not stop
  the pipeline. A logged warning that allows the build to continue is not a gate.
- **Missing logs determined the investigation limit** — six critical pieces of
  evidence were absent (see `pipeline_gaps.md`). Forensic readiness must be built
  before an incident, not during one.
- **Engineers are not just fixers — they are custodians of evidence and trust**
- CI/CD incidents spread quickly but can be stopped safely with reversible,
  ordered containment actions
- Post‑incident learning is part of the response, not an afterthought

---

## Reflection Prompt (Optional)

> What is **one realistic change** you could make in the next quarter that would make
> responding to a CI/CD incident safer and calmer?

Consider: In this scenario, all of the attack vectors were present in the STRIDE
threat model built in Lab 6. The attacker brute-forced credentials (Spoofing),
tampered with the pipeline definition (Tampering), and exfiltrated data through an
unsigned artifact (Information Disclosure). The threats were known. The question
is not whether to threat model — it is whether the identified mitigations were
actually implemented and verified.
# Lab 07 — Detection Engineering

## Overview

In this lab you will analyse a set of pre-prepared log files from a security incident on
the ESA Mission Registry API. You will practise the core detection engineering skills of
log analysis, attack reconstruction, and detection rule design — all without any SIEM
tooling.

**Estimated time:** 1.5 – 2 hours  
**Format:** Individual or pairs  
**Deliverable:** Written answers to each exercise, committed to your lab folder

---

## Prerequisites

- You have watched or attended the four Detection Engineering demos
  (`demos/detection/`)
- You are comfortable reading JSON and plain-text log files
- A text editor or terminal with `grep` / PowerShell available

---

## Background

On the night of **2026-04-14**, the ESA Mission Registry API was attacked.
The incident involved credential stuffing, bulk data exfiltration, and a CI/CD
pipeline compromise.

You have been given log files from two systems:

| File | System | Format |
|------|--------|--------|
| `demos/detection/attack-reconstruction/attack_sequence.jsonl` | API Gateway + Lambda | Structured JSON |
| `demos/detection/cicd-supply-chain/pipeline_suspicious.jsonl` | CodeBuild pipeline | Structured JSON |

You also have the attacker profile: `demos/detection/common_attacker_profile.md`

---

## Exercise 1 — Log Quality Assessment (20 min)

Open both files below side by side:

- `demos/detection/logquality/auth_bad.log`
- `demos/detection/logquality/auth_good.jsonl`

Both files log the **same authentication events** from the same system.

### Tasks

**1a.** List every field present in `auth_good.jsonl` that is **absent** from `auth_bad.log`.

**1b.** For each missing field, write one sentence explaining what detection capability
is lost without it.

**1c.** A security team receives an alert: *"Possible credential stuffing against the
login endpoint in the last 30 minutes."* 

Working only from `auth_bad.log`, write down every question from the list below that
you **cannot** answer with confidence:

- How many failed attempts were made?
- Which account was targeted?
- What IP address did the attempts come from?
- Was there a successful login after the failures?
- Were the attempts made by a human or an automated tool?
- How long did the attack last?

**1d.** Now answer all of the same questions from `auth_good.jsonl`.

---

## Exercise 2 — Attack Reconstruction (30 min)

Open `demos/detection/attack-reconstruction/attack_sequence.jsonl`.

You may use `grep`, PowerShell, or just read the file manually.

### Tasks

**2a.** Reconstruct the full attack timeline as a table with columns:

`Time (UTC) | Event | Actor | Asset Accessed | Outcome`

**2b.** Identify the **MITRE ATT&CK techniques** most likely represented by each phase.
Use the technique name and ID (e.g. *Brute Force — T1110*). You do not need to be exact —
a close match is fine.

**2c.** At what **exact log line** could an automated alert have fired?  
Write the detection rule in plain English:

> *"Alert when [condition] within [time window]."*

**2d.** The attacker attempted a `POST /missions` and received a `403`. 
What does this tell you about:
- The attacker's **intent**?
- The **effectiveness** of the RBAC control?
- What the attacker is likely to do **next**?

**2e.** One event in the log is marked `anomaly: unusually_large_response`.  
If this field did not exist, would you still be able to identify the event as suspicious?
What other fields or values give it away?

---

## Exercise 3 — CI/CD Pipeline Analysis (25 min)

Open both pipeline log files:

- `demos/detection/cicd-supply-chain/pipeline_normal.jsonl` (clean build)
- `demos/detection/cicd-supply-chain/pipeline_suspicious.jsonl` (compromised build)

### Tasks

**3a.** List every field or value in `pipeline_suspicious.jsonl` that differs from
`pipeline_normal.jsonl`. For each difference, state whether it is:
- A definite indicator of compromise (IOC)
- A suspicious anomaly worth investigating
- A benign difference with an innocent explanation

**3b.** The suspicious build has an `anomaly: sast_gate_bypassed` event.  
Explain in 2–3 sentences: what happened, why it is dangerous, and what the correct
pipeline behaviour should have been.

**3c.** Open `demos/detection/cicd-supply-chain/pipeline_gaps.md`.  
Pick **two** of the missing log types listed and explain:
- What data you would need to capture
- Where in the pipeline or infrastructure you would instrument it
- What detection rule you would write once the data was available

**3d.** Write a single paragraph summarising the attack for a non-technical stakeholder.
Include: what the attacker did, what data or systems were affected, and what stopped them
(if anything).

---

## Exercise 4 — Detection Rule Design (20 min)

Using what you observed across Exercises 2 and 3, design **three detection rules**.

For each rule, complete this template:

```
Rule Name:
Trigger Condition:
Log Source:
Fields Required:
Time Window:
Threshold:
Severity:
Suggested Response Action:
```

Your three rules must cover at least:
- One rule for the **credential stuffing** phase
- One rule for the **data exfiltration** phase  
- One rule for **CI/CD anomalies**

---

## Exercise 5 — Reflection (15 min)

Answer the following questions in your own words (3–5 sentences each):

**5a.** Looking at `demos/detection/debug-log-myth/debug_flood.log` — this application
was clearly logging a lot. Why would a developer argue this was sufficient? Why would a
security engineer disagree?

**5b.** At what point in the attack timeline was the **earliest opportunity** for a
human to have noticed something was wrong — assuming no automated alerting? What would
they have had to be looking at?

**5c.** The attacker used an account belonging to `k.petrov@external-contractor.io` —
a real contractor. The logs can tell you the account was used but cannot prove who was
sitting at the keyboard. What additional evidence sources (inside or outside AWS) might
help you attribute the activity to a specific individual?

**5d.** If you were the developer who built the ESA Mission Registry, what **one change**
to the logging design would have had the greatest impact on detectability? Justify your
choice by referencing a specific log line or missing field.

---

## Deliverable Structure

Create the following folder and files:

```
labs/detection/<your-name>/
├── exercise1-log-quality.md
├── exercise2-attack-reconstruction.md
├── exercise3-cicd-analysis.md
├── exercise4-detection-rules.md
└── exercise5-reflection.md
```

Commit and push to your branch before the debrief session.

---

## Peer Review Checklist

Swap with a partner and check their work against these criteria:

### Exercise 1
- [ ] All missing fields identified (minimum 6)?
- [ ] Each missing field linked to a specific detection capability?
- [ ] All 6 investigation questions correctly answered from `auth_good.jsonl`?

### Exercise 2
- [ ] Timeline table complete and in chronological order?
- [ ] ATT&CK techniques reasonable matches (doesn't need to be exact)?
- [ ] Detection rule is specific enough to implement — not just "alert on failed logins"?

### Exercise 3
- [ ] All 6 `anomaly` fields in `pipeline_suspicious.jsonl` identified?
- [ ] SAST bypass explanation covers all three required points?
- [ ] Stakeholder summary is jargon-free and accurate?

### Exercise 4
- [ ] Three rules present covering all three required phases?
- [ ] Each rule template fully completed?
- [ ] Thresholds are specific numbers, not vague ("5 attempts", not "many attempts")?

### Exercise 5
- [ ] Answers are specific — references to actual log lines or fields?
- [ ] Reflection shows understanding beyond repeating the demo content?

---

## Debrief Discussion Points

1. Which detection rule from Exercise 4 do you think is hardest to implement in practice,
   and why?
2. Did any log line in Exercise 3 surprise you — something you wouldn't have expected to
   be logged, or that you expected to be there but wasn't?
3. How would your answers to Exercise 2 change if the logs had been `debug_flood.log`
   instead of `attack_sequence.jsonl`?
4. The attacker succeeded in exfiltrating data despite every control in the system working
   as designed. What does that tell you about the relationship between access controls and
   detection?
5. What would need to change in your current team's development process for structured,
   security-relevant logging to become the default — not the exception?

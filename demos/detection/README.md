# Detection Engineering — Demo Suite

Four instructor-led or recorded demonstrations showing how logging design decisions
directly determine your ability to detect and investigate attacks.

All four demos use the **same fictional attacker** — see
[`common_attacker_profile.md`](common_attacker_profile.md) for the full background.

---

## The Story

On the night of **2026-04-14**, a compromised contractor account (`k.petrov@external-contractor.io`,
user ID `u-4892`) was used to:

1. Credential-stuff the ESA Mission Registry login endpoint for 16 minutes
2. Successfully authenticate and enumerate all three API collections (1,363 records total)
3. Attempt — and fail — a privilege escalation to write access
4. Harvest 847 mission records in a single bulk request
5. Later that same night, modify the CI/CD pipeline definition and exfiltrate build
   environment secrets via a malicious build

The four demos trace this attack from different angles, each teaching a distinct lesson
about detection engineering.

---

## Demo Overview

| # | Folder | Title | Core Lesson |
|---|--------|-------|-------------|
| 1 | [`logquality/`](logquality/) | Good vs Bad Application Logs | Log quality > log volume |
| 2 | [`attack-reconstruction/`](attack-reconstruction/) | Reconstructing an Attack Path | Correlation without tooling |
| 3 | [`cicd-supply-chain/`](cicd-supply-chain/) | CI/CD Supply Chain Abuse | Pipelines are a high-value attack surface |
| 4 | [`debug-log-myth/`](debug-log-myth/) | Why Debug Logs Don't Save You | Volume ≠ visibility |

---

## Demo 1 — Good vs Bad Application Logs

**Folder:** `logquality/`  
**Files:** `auth_bad.log`, `auth_good.jsonl`  
**Duration:** ~15 minutes

Shows the same authentication flow logged two ways. Version A (free-form) cannot answer
basic investigation questions. Version B (structured JSON) answers them immediately.

**Key question to ask students:**
> *"How many of these investigation questions can you answer from Version A?"*

See [`logquality/README.md`](logquality/README.md) for full run notes.

---

## Demo 2 — Reconstructing an Attack Path from Logs

**Folder:** `attack-reconstruction/`  
**Files:** `attack_sequence.jsonl`, `attack_sequence.csv`, `investigation_questions.md`  
**Duration:** ~20 minutes (5 min student exercise + 15 min debrief)

A single log file covering 21 events across the full kill chain. Students answer 5
investigation questions with no tooling. Makes the correlation thinking explicit.

**Instructor note:** `investigation_answers.md` is the instructor copy — do not
distribute to students before the exercise.

See [`attack-reconstruction/README.md`](attack-reconstruction/README.md) for run notes.

---

## Demo 3 — CI/CD Supply Chain Abuse

**Folder:** `cicd-supply-chain/`  
**Files:** `pipeline_normal.jsonl`, `pipeline_suspicious.jsonl`, `pipeline_gaps.md`  
**Duration:** ~15 minutes

A normal pipeline run followed by a compromised one. Six `anomaly` fields are seeded into
the suspicious run. Students spot the indicators, then discuss what logs were *missing*
and why that matters.

**Key moment:** The SAST gate was bypassed silently. Detection logged it — but the build
continued anyway.

See [`cicd-supply-chain/README.md`](cicd-supply-chain/README.md) for run notes.

---

## Demo 4 — Why Debug Logs Don't Save You

**Folder:** `debug-log-myth/`  
**Files:** `debug_flood.log`, `structured_forensic.jsonl`, `forensic_questions.md`  
**Duration:** ~15 minutes

200+ lines of debug logs vs 19 structured lines covering the same attack window.
Students attempt 5 forensic questions from the debug log first, then from the structured
log. The failure is visceral.

**Key message:** The logging design decision was made months before the incident.
By the time you need the logs, it is too late to improve them.

See [`debug-log-myth/README.md`](debug-log-myth/README.md) for run notes.

---

## Running All Four Demos in Sequence

The demos work best delivered **in order** — each one builds on the previous:

```
Demo 1  →  establishes what good logs look like
Demo 2  →  applies that to a real investigation (students do the work)
Demo 3  →  extends to CI/CD — a surface students often forget to log
Demo 4  →  closes with the myth-busting contrast (volume ≠ visibility)
```

Total delivery time: approximately **60–65 minutes** including discussion.

---

## Suggested Discussion Questions (End of Session)

1. Which of the `anomaly` fields in Demo 3 would your current system be able to generate?
2. If you had to add **one** field to your application logs tomorrow, what would it be?
3. At what point in Demo 2's kill chain could you have fired an automated alert?
4. Who in your team owns the decision about what gets logged — and when was it last reviewed?
5. What is the difference between a log that helps you debug and a log that helps you
   detect an attack? Can the same log line serve both purposes?

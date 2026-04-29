# Demo 2 — Reconstructing an Attack Path from Logs

## Purpose

Show correlation in action — **without any tooling**.

Students are given a single structured log file covering a complete attack sequence and
must answer 5 investigation questions using only their eyes, `grep`, or a text editor.
The exercise makes the thinking visible: no SIEM, no dashboard, no magic.

## Files

| File | Description |
|------|-------------|
| `attack_sequence.jsonl` | 21 structured log lines covering the full kill chain |
| `attack_sequence.csv` | Same data in CSV format (for students who prefer a spreadsheet) |
| `investigation_questions.md` | 5 questions — distribute to students |
| `investigation_answers.md` | Full answers with analysis — **instructor copy, do not distribute** |

## Run Order

1. Distribute `investigation_questions.md` (or show it on screen)
2. Give students **5 minutes** to answer using `attack_sequence.jsonl`
3. Debrief each question — use `investigation_answers.md` as the guide
4. Key discussion: *"What would have stopped this? What log line would have been the
   earliest possible detection point?"*

## The Kill Chain in the Logs

| Phase | Log Event | Time |
|-------|-----------|------|
| Reconnaissance / Initial Access | 14× `auth.login.failure` | 01:47 – 01:56 |
| Initial Access | `auth.login.success` (attempt 15) | 02:03 |
| Credential materialised | `auth.token.issued` | 02:03 |
| Discovery | `GET /missions` → 847 records | 02:05 |
| Discovery | `GET /satellites` → 312 records | 02:08 |
| Discovery | `GET /launches` → 204 records | 02:11 |
| Privilege Escalation (blocked) | `POST /missions` → 403 | 02:14 |
| Collection | `GET /missions?limit=1000` → 847 records | 02:15 |

## Earliest Detection Point

The **earliest possible detection** with these logs is `req-0002` — the second consecutive
failed login from `python-requests/2.31.0` on the same IP. A rule firing on:

> *5 or more `auth.login.failure` events from the same `source_ip` within 10 minutes*

would have triggered an alert **16 minutes before the attacker succeeded**.

This is only possible because the logs contain `source_ip` and `attempt_number`.
In `demo1-log-quality/auth_bad.log`, neither field exists — the same rule cannot be written.

## Connection to the Attacker Profile

The events cover `k.petrov@external-contractor.io` / `u-4892` / `185.220.101.47`
on 2026-04-14. See `demos/detection/common_attacker_profile.md` for the full timeline
including the CI/CD activity that followed.

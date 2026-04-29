# Demo 4 — Why Debug Logs Don't Save You During an Incident

## Purpose

Kill the myth that *"we log a lot, so we're fine."*

The same attack — credential stuffing followed by bulk data exfiltration — is shown through
two different log files from the same system. One has hundreds of lines. The other has
fewer than twenty. Only one of them is useful during an incident.

## Files

| File | Description |
|------|-------------|
| `debug_flood.log` | 200+ lines of debug-level logs covering the same events |
| `structured_forensic.jsonl` | 19 structured JSON log lines covering the same events |
| `forensic_questions.md` | 5 investigation questions — attempt with debug log first |

## Run Order

1. Open `forensic_questions.md` — read the questions aloud
2. Give students **3 minutes** to attempt answers using `debug_flood.log`
3. Ask: *"How many questions could you answer with confidence?"*
4. Open `structured_forensic.jsonl` — answer all 5 questions in under 60 seconds
5. Walk through the contrast table below

## Contrast Table

| Forensic Need | `debug_flood.log` | `structured_forensic.jsonl` |
|---------------|-------------------|-----------------------------|
| Who made the requests? | ❌ No user ID anywhere | ✅ `user_id` on every event |
| Where did the requests come from? | ❌ No IP address logged | ✅ `source_ip` on every event |
| How many failed logins before success? | ❌ Can count manually, but no link to identity | ✅ `attempt_number` field, linked to `username` |
| Was a privilege escalation attempted? | ⚠️ `handler returned 403` — but for which endpoint, which user? | ✅ `event: api.authorization.failure` with `user_id`, `path`, `required_role`, `actual_role` |
| Was bulk data harvested intentionally? | ❌ `serialising 847 records` — no context about whether this is normal | ✅ `anomaly: unusually_large_response` + `query_params: {limit: 1000}` |
| Can you correlate login to API calls? | ❌ No shared identifier across events | ✅ `request_id` links token issuance to the triggering login event |

## Key Teaching Points

1. **Volume is not visibility.** `debug_flood.log` has 10× more lines than
   `structured_forensic.jsonl` — and answers fewer questions.

2. **Debug logs are for developers, not defenders.** They tell you *what the code did*,
   not *who asked it to do it* or *whether it should have*.

3. **The fields that matter for security are a design decision.** `user_id`, `source_ip`,
   `outcome`, `request_id` — none of these appear automatically. Someone had to decide to
   log them. That decision happens at development time, not incident time.

4. **By the time you need the logs, it's too late to improve them.** The attacker
   `u-4892` exfiltrated 847 records. With `debug_flood.log`, you cannot prove who did it,
   from where, or how many times they had tried before succeeding.

## Connection to the Attacker Profile

The events in both files cover the same window of `k.petrov@external-contractor.io`'s
attack on 2026-04-14 (`u-4892`, IP `185.220.101.47`).

See `demos/detection/common_attacker_profile.md` for the full timeline.

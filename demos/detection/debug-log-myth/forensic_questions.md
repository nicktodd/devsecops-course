# Demo 4 — Forensic Questions

You are investigating a potential security incident on the ESA Mission Registry API.
You have been given the application logs from the night of **2026-04-14**.

**First, try to answer these questions using `debug_flood.log`.**  
Then try again with `structured_forensic.jsonl`.

---

## Questions

### Q1 — Credential Attack
> Was there a brute-force or credential stuffing attack against the login endpoint?  
> If so: who was targeted, how many attempts were made, and over what time period?

### Q2 — Identity of the Successful Caller
> At 02:03, a login succeeded. Who logged in?  
> What was their username, user ID, source IP address, and assigned role?

### Q3 — Privilege Escalation Attempt
> Did the authenticated user attempt to perform any action beyond their permissions?  
> If so: what did they try to do, at what time, and what was the result?

### Q4 — Data Exfiltration
> At 02:15, a large amount of data was returned.  
> Can you confirm: how many records were returned, and is there any indication this was intentional?

### Q5 — The Unanswerable Question
> Using only `debug_flood.log`: can you prove that the same person was responsible for  
> all 14 failed logins, the successful login, and the subsequent API calls?  
> What field would you need that is missing?

---

> ✅ The answer to every question is immediately visible in `structured_forensic.jsonl`.  
> In `debug_flood.log`, Q1–Q4 cannot be answered with certainty, and Q5 cannot be answered at all.

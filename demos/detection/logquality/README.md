# Demo 1 — What a Good vs Bad Application Log Looks Like

## Purpose

Show that **log quality matters more than log volume**.  
The same authentication flow — including a suspicious login — is logged two ways.  
Version A makes investigation nearly impossible. Version B answers every question in seconds.

## Run Order

1. Open `auth_bad.log` — ask: *"Did anything suspicious happen in the last hour?"*
2. Open `auth_good.jsonl` — ask the same question
3. Walk through the contrast questions below

## Discussion Questions

| Question | Answerable in Version A? | Answerable in Version B? |
|----------|--------------------------|--------------------------|
| How many failed logins did `u-4892` have before succeeding? | ❌ No user ID in failures | ✅ Filter `user_id=u-4892`, `outcome=failure` |
| What IP did the successful login come from? | ❌ IP only in some lines | ✅ `source_ip` on every event |
| How long between first failure and success? | ❌ Inconsistent timestamps | ✅ `timestamp` on every event, ISO-8601 |
| Was a token issued after login? | ❌ Can't correlate events | ✅ `request_id` links login → token issuance |
| Was this the only session from that IP? | ❌ No way to know | ✅ Filter `source_ip=185.220.101.47` |

## Key Teaching Moment

> Detection quality is usually limited by logging design choices made months earlier.  
> By the time an incident occurs, it is too late to improve your logs.

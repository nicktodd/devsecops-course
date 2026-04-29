# Demo 3 — CI/CD Supply Chain Abuse

## Purpose

Show that CI/CD pipelines are a high-value attack target, and that logs can reveal
a supply chain compromise — if the right events are being captured.

## Run Order

1. Open `pipeline_normal.jsonl` — walk through a clean build from push to deploy
2. Open `pipeline_suspicious.jsonl` — same pipeline, same commit author, but something is wrong
3. Ask: *"How many suspicious indicators can you spot before I tell you?"*
4. Walk through each `anomaly` field and the `pipeline_gaps.md` missing-log discussion

## Contrast Points

| Normal Build | Suspicious Build |
|---|---|
| Triggered by `n.todd@watchelm.com` at 09:02 | Triggered by `k.petrov@external-contractor.io` at 02:44 |
| No sensitive file changes | `buildspec.yml` modified in preceding commit |
| SAST: 0 HIGH findings | SAST: 1 HIGH finding — **build continued anyway** |
| No outbound network calls | Outbound HTTPS to `198.51.100.42` during BUILD phase |
| Artifact: 18,432 bytes | Artifact: 19,104 bytes — 672 bytes larger |
| No new environment variables | `EXFIL_ENDPOINT` added 12 minutes before build |

## Connection to STRIDE Analysis

This demo directly demonstrates:
- **T-11** — S3 build artefact tampering
- **T-12** — SAM template parameter injection  
- **T-32** — CodeBuild role over-privilege
- **T-33** — Dependency confusion / supply chain attack

The attacker is the same `u-4892` / `k.petrov@external-contractor.io` from Demo 1 and 2,
now operating from a second IP (`91.108.4.212`) in a separate GitHub session —
suggesting the contractor account credentials were shared or the same person used a
different exit node for the pipeline activity.

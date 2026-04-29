# Demo 3 — CI/CD Log Gaps

## Indicators Present in `pipeline_suspicious.jsonl`

| # | Event | Field | Why It Matters |
|---|-------|-------|----------------|
| 1 | `github.sensitive_file_changed` | `file: buildspec.yml` | Pipeline definition modified — any attacker who can change this controls what runs in production |
| 2 | `codebuild.environment_variable.added` | `variable_name: EXFIL_ENDPOINT` | A new secret added immediately before a suspicious build — classic staging for exfiltration |
| 3 | `pipeline.triggered` | `anomaly: outside_business_hours` | Build at 02:44 UTC — no legitimate deployment should run at this time |
| 4 | `pipeline.sast.threshold_breached` | `anomaly: sast_gate_bypassed` | SAST found a HIGH severity issue but the build continued — gate was silently disabled |
| 5 | `pipeline.network.outbound` | `anomaly: unexpected_outbound_connection` | Build phase made an outbound HTTPS call to an unknown IP — not part of the normal build |
| 6 | `pipeline.artifact.uploaded` | `anomaly: artifact_size_increased` | Packaged template 672 bytes larger than yesterday's identical build — possible payload injection |

---

## Logs That Were Missing — And Why That Matters

| What Should Have Been Logged | Why It Was Absent | Impact |
|------------------------------|------------------|--------|
| **Who approved the `buildspec.yml` change** | No branch protection / required reviewer on `main` | Cannot prove whether the change was reviewed or unilaterally pushed |
| **Previous value of `EXFIL_ENDPOINT`** | CodeBuild environment variable history is not logged by default | Cannot tell if this variable existed before or was freshly created |
| **The content of the outbound request** | Network egress logging not enabled on CodeBuild | Cannot confirm what data was sent to `198.51.100.42` |
| **What the `curl` command actually received back** | Same — no response capture | Cannot determine if the exfiltration succeeded |
| **Diff of the SAM template before/after deploy** | CloudFormation change sets not stored | Cannot tell what changed in the deployed infrastructure |
| **Identity of who disabled the SAST gate** | `buildspec.yml` change only shows commit, not code review | The gate bypass may have been intentional sabotage or an accident |

---

## Key Teaching Points

1. **Changing a pipeline definition is a privileged action.** It should require the same
   approval as a production deployment. In this case, `k.petrov` (an analyst, not an admin)
   was able to push directly to `main` and modify `buildspec.yml`.

2. **The SAST gate was bypassed silently.** The build logged the threshold breach but
   continued anyway. A properly configured gate would have exited with a non-zero code,
   failing the build. Detection is useless if it doesn't trigger a stop.

3. **Outbound network calls during a build are a red flag.** A SAM build should only call
   AWS APIs. Any connection to an external IP during `BUILD` phase is an anomaly worth
   alerting on.

4. **Artifact size is a cheap integrity signal.** A 3.5% size increase on an otherwise
   identical commit is suspicious. Comparing artifact hashes between builds costs nothing
   and would have flagged this immediately.

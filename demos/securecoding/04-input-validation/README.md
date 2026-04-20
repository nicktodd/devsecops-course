# Input Validation Fundamentals

## What Is It?

Input validation is the practice of verifying that data entering a system
conforms to the expected type, format, range, and length **before** it is
used by business logic, stored in a database, or passed to an interpreter.

Without validation at system boundaries, attackers can:

- Supply unexpected types that cause arithmetic errors or silent corruption
- Send out-of-range values that bypass downstream safety checks
- Trigger unhandled exceptions that return internal stack traces to the caller
- Feed oversized payloads that degrade performance or fill logs

**Allowlists over blocklists** — Defining what is acceptable (regex, range, type)
is far more robust than trying to enumerate every malformed variant to reject.
Blocklists are routinely bypassed by encoding, casing, or canonicalization tricks.

**Validate at the boundary** — Validation that happens deep inside business logic
has already allowed the untrusted value to travel through the codebase.
The boundary check must happen first — before the data reaches anything that acts on it.

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/app.py` | Satellite command endpoint — no type, range, length, or format checks |
| `fixed/app.py` | Same endpoint — Pydantic model validates all fields at the entry point |

## How to Run

### Prerequisites

```bash
pip install flask pydantic
```

---

### Vulnerable Version

```bash
cd vulnerable
python app.py
```

**Wrong type for altitude — silently accepted, breaks arithmetic:**

```bash
curl -s -X POST http://127.0.0.1:5000/command \
    -H "Content-Type: application/json" \
    -d '{"command_name":"ORBIT_ADJUST","altitude_km":"high","target_id":"SAT-0001"}'
```

Response attempts string multiplication, producing nonsense:

```json
{"altitude_km": "high", "burn_duration": "highhighhigh...", "status": "dispatched"}
```

**Missing field — Python KeyError traceback returned to caller:**

```bash
curl -s -X POST http://127.0.0.1:5000/command \
    -H "Content-Type: application/json" \
    -d '{"command_name":"ORBIT_ADJUST"}'
```

Returns a 500 with the full Python traceback — revealing file paths and code structure.

**Negative altitude — below-LEO value accepted silently:**

```bash
curl -s -X POST http://127.0.0.1:5000/command \
    -H "Content-Type: application/json" \
    -d '{"command_name":"ORBIT_ADJUST","altitude_km":-99999,"target_id":"SAT-0001"}'
# {"altitude_km": -99999, "burn_duration": -41999.58, "status": "dispatched"}
```

---

### Fixed Version

```bash
cd fixed
python app.py
```

**Wrong type — rejected with a structured 400:**

```bash
curl -s -X POST http://127.0.0.1:5000/command \
    -H "Content-Type: application/json" \
    -d '{"command_name":"ORBIT_ADJUST","altitude_km":"high","target_id":"SAT-0001"}'
```

```json
{"errors": [{"field": "altitude_km", "message": "Input should be a valid integer, unable to parse string as an integer"}]}
```

**Out-of-range altitude — rejected:**

```bash
curl -s -X POST http://127.0.0.1:5000/command \
    -H "Content-Type: application/json" \
    -d '{"command_name":"ORBIT_ADJUST","altitude_km":-99999,"target_id":"SAT-0001"}'
```

```json
{"errors": [{"field": "altitude_km", "message": "Input should be greater than or equal to 200"}]}
```

**Invalid command_name format — rejected:**

```bash
curl -s -X POST http://127.0.0.1:5000/command \
    -H "Content-Type: application/json" \
    -d '{"command_name":"orbit adjust; rm -rf /","altitude_km":400,"target_id":"SAT-0001"}'
```

```json
{"errors": [{"field": "command_name", "message": "String should match pattern '^[A-Z_]+$'"}]}
```

**Valid request — accepted:**

```bash
curl -s -X POST http://127.0.0.1:5000/command \
    -H "Content-Type: application/json" \
    -d '{"command_name":"ORBIT_ADJUST","altitude_km":400,"target_id":"SAT-0042"}'
```

```json
{"altitude_km": 400, "burn_duration": 168.0, "command": "ORBIT_ADJUST", "status": "dispatched", "target": "SAT-0042"}
```

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Type enforcement | None — `"high"` accepted for altitude | Pydantic rejects non-integer altitude at parse time |
| Range validation | None — negative altitude accepted | `ge=200, le=36_000` on `altitude_km` |
| Length limit | None — 10,000-char command_name accepted | `max_length=32` on `command_name` |
| Format check | None — any string for `target_id` | `pattern=r"^SAT-\d{4}$"` enforced by regex allowlist |
| Unknown fields | Silently ignored | `extra="forbid"` rejects unexpected fields |
| Error responses | Unhandled `KeyError` / full traceback | Generic 400 with field-level messages; no internals |
| Validation location | After use in business logic | At system boundary — before any business logic runs |

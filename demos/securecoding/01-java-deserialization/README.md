# Java Deserialization Risks

## What Is It?

Java's native serialisation mechanism (`ObjectInputStream.readObject()`) can
instantiate and initialise any `Serializable` class on the server's classpath.
When the server accepts serialised byte streams from untrusted sources — over
HTTP, message queues, or caching layers — an attacker can craft a stream that
references a class whose custom `readObject()` method performs a dangerous action.

This is called a **deserialization gadget chain**. Real-world examples
(ysoserial payloads, Apache Commons Collections RCE, Spring Framework gadgets)
exploit classes already present as legitimate server dependencies, meaning no
additional code needs to be planted — the server's own classpath is the weapon.

The attack sequence:
1. Attacker identifies a `Serializable` class on the target classpath with a dangerous `readObject()` hook.
2. Attacker serialises that class with chosen field values and sends the bytes.
3. The server calls `ObjectInputStream.readObject()` — the gadget fires before the server can inspect the object type.

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/DataTransferServer.java` | HTTP server that calls `readObject()` with no class filtering |
| `vulnerable/GadgetPayload.java` | Attacker-controlled class; `readObject()` executes an OS command |
| `vulnerable/ExploitGenerator.java` | Serialises `GadgetPayload` to `payload.ser` for delivery |
| `fixed/TelemetryRecord.java` | The only safe DTO the server should ever deserialise |
| `fixed/DataTransferServerFiltered.java` | Fix A — `ObjectInputFilter` allowlist; still accepts binary serialisation |
| `fixed/DataTransferServerJson.java` | Fix B — Jackson JSON; `ObjectInputStream` eliminated entirely |
| `fixed/pom.xml` | Maven build for the Jackson variant |

## How to Run

### Prerequisites

- Java 17+ JDK (`javac`, `java`)
- `curl`
- For Fix B (JSON server): Maven, or manually download `jackson-databind-2.17.1.jar`

---

### Vulnerable Version — Gadget Chain Execution

**Step 1 — Compile all three source files:**

```bash
cd vulnerable
javac DataTransferServer.java GadgetPayload.java ExploitGenerator.java
```

**Step 2 — Start the server:**

```bash
java DataTransferServer
# [SERVER] Vulnerable telemetry server listening on :8080
```

**Step 3 — Generate the exploit payload (in a second terminal):**

```bash
java ExploitGenerator
# [EXPLOIT] Serialised GadgetPayload written to payload.ser (...)
# [EXPLOIT] Send it: curl -X POST http://localhost:8080/telemetry ...
```

**Step 4 — Send the payload:**

```bash
curl -X POST http://localhost:8080/telemetry \
    --data-binary @payload.ser \
    -H "Content-Type: application/octet-stream"
```

**Server output shows the gadget fired:**

```
[SERVER] Received 287 bytes — deserialising...
[GADGET] readObject() triggered automatically — executing: touch /tmp/pwned_by_deserialization
[GADGET] Process started (PID 12345) — attacker code executed.
[SERVER] Deserialised object of type: GadgetPayload
```

The file `/tmp/pwned_by_deserialization` (or `%TEMP%\pwned_by_deserialization.txt` on Windows)
is created — proving arbitrary code executed during deserialisation.

---

### Fixed Version A — ObjectInputFilter Allowlist

The server accepts the same binary wire format but rejects any class
not on the explicit allowlist before `readObject()` can run.

```bash
cd fixed
# Copy GadgetPayload onto the fixed server's classpath (simulates it being a
# legitimate dependency — as it would be in a real Apache Commons Collections attack)
cp ../vulnerable/GadgetPayload.java .
javac TelemetryRecord.java GadgetPayload.java DataTransferServerFiltered.java
java DataTransferServerFiltered
```

**Send the same gadget payload:**

```bash
curl -X POST http://localhost:8080/telemetry \
    --data-binary @../vulnerable/payload.ser \
    -H "Content-Type: application/octet-stream"
# Returns 400: Rejected: class not permitted
```

**Server output — filter rejects before gadget fires:**

```
[FILTER] REJECTED class not on allowlist: GadgetPayload
[SERVER] Stream rejected by filter: filter status REJECTED ...
```

The `[GADGET]` line never appears — `readObject()` was never called.

---

### Fixed Version B — JSON (preferred for new services)

```bash
cd fixed
mvn package -q
java -jar target/telemetry-server-json-1.0.0.jar
```

**Send a valid telemetry record:**

```bash
curl -X POST http://localhost:8080/telemetry \
    -H "Content-Type: application/json" \
    -d '{"satelliteId":"ESA-01","altitudeKm":408.5,"signalStrengthDbm":-78.2,"timestampEpochMs":1745000000}'
# OK: TelemetryRecord{id='ESA-01', altKm=408.5, signal=-78.2dBm, ts=1745000000}
```

**Attempt to inject a type hint gadget:**

```bash
curl -X POST http://localhost:8080/telemetry \
    -H "Content-Type: application/json" \
    -d '{"@class":"GadgetPayload","command":"touch /tmp/pwned"}'
# 400 Bad request — unknown field @class rejected
```

There is no `ObjectInputStream` in the JSON server. No gadget chain is possible.

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Class filtering | None — any classpath class accepted | ObjectInputFilter allowlist: only `TelemetryRecord` + `String` |
| Gadget execution | `readObject()` called before type can be checked | Filter rejects at class-resolution time; `readObject()` never called |
| Wire format (preferred) | Binary Java serialisation | JSON via Jackson — `ObjectInputStream` eliminated |
| Unknown fields | N/A | `FAIL_ON_UNKNOWN_PROPERTIES=true` rejects `@class` type hints |
| Attack surface | Entire server classpath | One schema-bound DTO |

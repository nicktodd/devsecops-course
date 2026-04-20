# C and C++ Memory Safety

## What Is It?

C and C++ give programmers direct control over memory. When that control is
exercised incorrectly — or when attacker-supplied data reaches memory operations
without bounds checking — the result is memory corruption. The three most
exploited classes are:

| Class | Root Cause | Typical Impact |
|---|---|---|
| Buffer overflow | Writing beyond the end of an allocated buffer | Stack/heap corruption, RCE via return-address overwrite |
| Use-after-free | Dereferencing a pointer after its memory is freed | Read/write of attacker-influenced heap data, RCE |
| Double-free | Calling `free()` on the same pointer twice | Allocator metadata corruption, write-what-where primitive |

### Heartbleed (CVE-2014-0160)

Heartbleed is the canonical example of a bounds-check omission. The OpenSSL
TLS heartbeat handler copied `claimed_length` bytes from the incoming packet
into the response — where `claimed_length` was a 2-byte attacker-controlled
field and was never validated against the number of bytes actually received.

A single `if (claimed_length > actual_length) return 0;` would have prevented
up to 64 KB of heap memory — including private keys, session tokens, and
passwords — being disclosed per request, with no authentication required.

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/memory_bugs.c` | Buffer overflow, use-after-free, double-free in isolation |
| `vulnerable/heartbleed_sim.c` | Heartbleed root cause — unchecked `memcpy` discloses adjacent heap |
| `vulnerable/Makefile` | Plain `gcc -g` build — no hardening |
| `fixed/memory_bugs.c` | All three bugs corrected with safe patterns |
| `fixed/heartbleed_sim.c` | Single bounds check added; attacker gets nothing |
| `fixed/Makefile` | Hardened build with ASan, stack canaries, and FORTIFY_SOURCE |

## How to Run

### Prerequisites

- `gcc` (or `clang` — substitute `CC=clang` in the Makefile)
- Linux, macOS, or WSL on Windows

---

### Vulnerable Version

```bash
cd vulnerable
make
```

**Buffer overflow:**

```bash
./memory_bugs overflow "AAAAAAAAAAAAAAAAAAA"
# Copies 19 bytes into a 16-byte buffer — stack corruption
# Without ASan the output may appear normal; the damage is silent
```

**Use-after-free:**

```bash
./memory_bugs uaf
# Reads freed memory — undefined behaviour, may show stale or garbage data
```

**Double-free:**

```bash
./memory_bugs doublefree
# glibc will usually abort: "free(): double free detected in tcache 2"
```

**Heartbleed — 200-byte over-read discloses adjacent heap secrets:**

```bash
./heartbleed_sim
```

Expected output:

```
--- Attacker sends heartbeat with claimed_length=200, actual=4 ---
  Sending 200 bytes (actual payload was 4 bytes):
  [PING.SESSION_TOKEN=esa-orbit-key-a1b2c3d4......PRIVATE_KEY_FRAGMENT=MIIEpAIBAAKCAQ==...]
  ^ 196 bytes of LEAKED heap memory visible above the 'PING' payload
```

---

### Fixed Version — All Bugs Caught by AddressSanitizer

```bash
cd fixed
make
```

**Buffer overflow — truncated at 15 chars, no overrun:**

```bash
./memory_bugs overflow "AAAAAAAAAAAAAAAAAAA"
# [overflow] Safely copied into buf[16]: "AAAAAAAAAAAAAAA"
# [overflow] Input was truncated to 15 characters — no overflow.
```

**Use-after-free — NULL pointer guard prevents access:**

```bash
./memory_bugs uaf
# [uaf] Pointer is NULL after free — safe.
```

**Double-free — free(NULL) is a safe no-op:**

```bash
./memory_bugs doublefree
# [doublefree] Second free(NULL) — no heap corruption.
```

**Heartbleed — over-read request rejected before memcpy:**

```bash
./heartbleed_sim
```

Expected output:

```
--- Attacker sends heartbeat with claimed_length=200, actual=4 ---
  [HEARTBEAT] REJECTED: claimed_length=200 > actual_length=4 (potential over-read of 196 bytes — request discarded)
  No data returned. No secrets disclosed.

--- Legitimate client sends heartbeat with claimed_length=4 ---
  Sending 4 bytes (within bounds):
  [PING]
```

### Verify with AddressSanitizer

Compile the **vulnerable** version with ASan to see precise diagnostics:

```bash
cd vulnerable
gcc -g -fsanitize=address,undefined -o memory_bugs_asan memory_bugs.c
./memory_bugs_asan overflow "AAAAAAAAAAAAAAAAAAA"
```

ASan output (abridged):

```
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x... 
WRITE of size 20 at 0x... thread T0
    #0 0x... in demo_buffer_overflow memory_bugs.c:41
    #1 0x... in main memory_bugs.c:77
...
Shadow bytes around the buggy address:
  ...
  0x...: 00 00 00 00 f2 f2 f2 f2  ← red zone (f2 = stack right redzone)
```

The fixed/ Makefile enables these flags by default — making every build a
security-hardened test build during development.

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Buffer copy | `strcpy(buf, input)` — no length limit | `strncpy(buf, input, sizeof(buf)-1)` + explicit NUL |
| malloc result | Unchecked — NULL pointer dereference possible | `if (!ptr) { perror("malloc"); return; }` |
| Use-after-free | Pointer used after `free()` | `ptr = NULL` immediately after `free()` |
| Double-free | `free(ptr)` called twice | `ptr = NULL` after first `free()`; `free(NULL)` is a no-op |
| Heartbleed bounds | `memcpy(response, payload, claimed_length)` — no check | `if (claimed_length > actual_length) return;` before `memcpy` |
| Build hardening | None | `-fsanitize=address,undefined -fstack-protector-all -D_FORTIFY_SOURCE=2` |

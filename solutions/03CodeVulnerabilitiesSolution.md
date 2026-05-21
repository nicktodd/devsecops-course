# Solution Guide: Secure Coding – Identifying and Fixing Vulnerabilities

## Purpose

This guide provides **reference answers and reasoning** for the Secure Coding lab.

The goal is not just correct answers, but understanding:

- how to recognise vulnerability patterns
- how to reason about root cause
- how to classify and prioritise issues in real codebases

---

## Exercise 1 – SQL Injection

### Vulnerability

SQL Injection. User-supplied input is concatenated directly into a SQL query string without sanitisation or parameterisation.

### Why it happens

The code treats user input as trusted and part of the query structure rather than as data. An attacker can supply a value such as `1 OR 1=1` or `1; DROP TABLE users--` to manipulate the query.

### Fix

Use parameterised queries or a prepared statement:

    query = "SELECT * FROM users WHERE id = ?"
    db.execute(query, (user_id,))

### Classification

Coding issue — a parameterised query is the expected pattern; the developer used string concatenation instead.

---

## Exercise 2 – Cross-Site Scripting (XSS)

### Risk

Reflected or stored XSS. If `username` contains HTML or JavaScript (e.g. `<script>alert(1)</script>`), it will be rendered and executed in the victim's browser.

### Why input validation alone is not sufficient

Validation checks whether input is acceptable, but does not transform it. A value can pass validation and still contain characters that are dangerous when rendered as HTML. Output encoding is a separate, necessary control.

### Fix

Encode the value at the point of output for the target context (HTML entity encoding):

    <div>
      Welcome, {{ username | escape }}
    </div>

Most modern templating engines auto-escape by default — confirm this is enabled and never disable it for user-controlled values.

### Classification

Coding issue — the template renders raw user input without encoding at the output point.

---

## Exercise 3 – Unsafe Deserialisation

### Why it is dangerous

Java's `ObjectInputStream.readObject()` deserialises arbitrary bytes from the stream into live Java objects. An attacker who controls the input stream can send a crafted payload that triggers arbitrary code execution during deserialisation, before any type-check occurs.

### Attack type

Remote Code Execution (RCE) via gadget chains. Libraries such as Apache Commons Collections or Spring have historically contained gadget chains exploitable in this way.

### Safer alternatives

- Use a data-only format such as JSON or XML with a strict schema, parsed by a library that does not instantiate arbitrary objects.
- If Java serialisation must be used, apply a deserialization filter (`ObjectInputFilter`) to allowlist expected classes.
- Validate the source and integrity of the stream before deserialising.

### Classification

Design issue — the architectural decision to accept and deserialise raw Java objects from an untrusted network stream is inherently unsafe, regardless of how carefully the code is written.

---

## Exercise 4 – Buffer Overflow

### Vulnerability type

Stack-based buffer overflow. `strcpy` copies bytes from `user_input` into a fixed 10-byte buffer with no bounds checking.

### Root cause

C's standard string functions (`strcpy`, `gets`, `sprintf`) do not perform length checks. If `user_input` exceeds 9 characters (plus null terminator), it overwrites adjacent memory on the stack.

### Why dangerous even without an immediate crash

Overwritten stack memory can corrupt the return address, enabling an attacker to redirect execution to arbitrary code (classic RCE). Even if a crash is suppressed, the process is in an inconsistent state. The absence of a visible crash does not imply safety — it may indicate a silent, successful exploit.

### Fix

Use bounded alternatives:

    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

Better still, use a higher-level language or a safe string library that manages bounds automatically.

### Classification

Coding issue — the developer chose an unsafe function where a bounded alternative exists and is well known.

---

## Exercise 5 – Dependency Management

### Risks

- No version pins: any `pip install` will pull the latest available version, which may introduce breaking changes or a newly published malicious release.
- `internal-utils` is an ambiguous package name. Dependency confusion attacks exploit the fact that public package registries are checked before private ones; an attacker can publish a malicious `internal-utils` to PyPI and have it installed automatically.
- No integrity verification (no hashes, no lock file).

### Attack patterns

- **Dependency confusion / namespace confusion**: publish a higher-versioned package with the same name to a public registry.
- **Typosquatting**: publish a package with a name close to a popular dependency.
- **Supply chain compromise**: compromise the upstream package maintainer and inject malicious code into a legitimate release.

### Secure dependency management

- Pin all dependencies to exact versions: `flask==3.0.3`
- Use a lock file (`pip-compile`, `poetry.lock`) and commit it to source control.
- Enable hash verification: `pip install --require-hashes -r requirements.txt`
- Configure the package manager to use a trusted private mirror for internal packages and prevent fallback to the public registry.
- Scan dependencies for known CVEs in CI (e.g. `pip-audit`, Dependabot, Snyk).

### Classification

Configuration issue — the problems stem from how the dependency file is configured (unpinned versions, ambiguous names, no integrity checks), not from the application logic itself.

---

## Exercise 6 – Weak Cryptography

### What is wrong

MD5 is a message digest algorithm, not a password hashing function. It is:

- **Fast** — an attacker with GPU hardware can compute billions of MD5 hashes per second, making brute-force and dictionary attacks trivial.
- **Broken for collision resistance** — though less relevant for passwords, the algorithm has fundamental weaknesses.
- **Unsalted** — identical passwords produce identical hashes, enabling rainbow table lookups.

### Why MD5 is unsuitable

Password hashing requires a function that is deliberately slow and includes a per-user salt. MD5 was designed for speed and data integrity, not for resisting offline brute-force attacks.

### What to use instead

Use a purpose-built password hashing function:

- **bcrypt** — widely supported, configurable cost factor
- **Argon2** (preferred) — winner of the Password Hashing Competition, memory-hard
- **PBKDF2** — acceptable, FIPS-compliant option

Example using `bcrypt` in Python:

    import bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

### Classification

Coding issue — a more secure algorithm exists and should have been selected. This is a mistake in implementation choice rather than system architecture.

---

## Exercise 7 – Path Traversal

### Risk

Path traversal (also called directory traversal). An attacker can supply a value such as `../../etc/passwd` or `../../app/config.py`, causing the application to open files outside the intended `/data/` directory.

### Why it is dangerous

The application does not validate or canonicalise the filename before constructing the path. String concatenation alone does not prevent escape sequences (`../`) from being interpreted by the operating system.

### Validation and controls

- **Canonicalise** the path and verify it starts with the expected base directory:

      import os
      base = "/data/"
      requested = os.path.realpath(os.path.join(base, filename))
      if not requested.startswith(os.path.realpath(base)):
          raise ValueError("Invalid file path")

- **Allowlist** filenames against a known set of permitted values rather than accepting arbitrary input.
- Apply the principle of least privilege: the process should only have read access to the files it legitimately needs to serve.

### Classification

Coding issue — the developer concatenated user input into a file path without canonicalisation or boundary checks.

---

## Exercise 8 – Prioritisation

### Suggested Top 3

**1. Exercise 4 – Buffer Overflow (C memory safety)**
- Exploitability: high — well-understood class of vulnerability with public exploit techniques
- Impact: critical — potential for arbitrary code execution and full process compromise
- Blast radius: broad — the entire host running this process is at risk

**2. Exercise 1 – SQL Injection**
- Exploitability: high — trivial to exploit with widely available tooling
- Impact: critical — full database read/write/delete, potential for data breach and compliance failure
- Likelihood: very common — consistently in the OWASP Top 10

**3. Exercise 3 – Unsafe Deserialisation**
- Exploitability: moderate-high (requires knowledge of gadget chains, but tooling exists)
- Impact: critical — remote code execution
- Blast radius: extends beyond the application to any system accessible from the compromised process

### Reasoning approach

Prioritise based on:

- **Exploitability**: how easily can an attacker trigger this in practice?
- **Impact**: what is the worst-case outcome if exploited?
- **Likelihood**: how commonly is this vulnerability exploited in the wild?
- **Blast radius**: how many systems, users, or data sets are affected?

---

## Exercise 9 – Missing Controls

| Exercise | Vulnerability | Missing Control |
|----------|--------------|----------------|
| 1 | SQL Injection | Input validation / parameterised queries |
| 2 | XSS | Output encoding |
| 3 | Unsafe Deserialisation | Trust boundary enforcement |
| 4 | Buffer Overflow | Safe memory handling |
| 5 | Dependency Management | Secure dependency management |
| 6 | Weak Password Hashing | Strong cryptography |
| 7 | Path Traversal | Input validation |

---

## Reflection

### Pattern Recognition

The most frequent pattern across all exercises is **trusting user input** — either by embedding it directly in queries, rendering it without encoding, passing it to unsafe functions, or using it to construct file paths.

A secondary pattern is **unsafe defaults**: MD5 as a hash function, unpinned dependencies, and unsafe C string functions are all defaults or convenience choices that introduce risk.

### Key Insight

Most of these vulnerabilities are not obscure edge cases — they are well-known, well-documented, and preventable. The root cause is often not ignorance of security, but the absence of secure defaults, code review focused on correctness rather than safety, or time pressure that leads developers to reach for the quickest solution.

### Design vs Coding vs Configuration

Only one exercise (Exercise 3) is a **design** issue — the decision to trust raw serialised objects from the network is fundamentally unsafe before any code is written.

Exercise 5 is a **configuration** issue — the application code is not at fault; the way the build system is configured introduces the risk.

All other exercises are **coding** issues — the vulnerability arises from a specific implementation choice that a developer made, where a safer alternative existed and was available.

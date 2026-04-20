# Python Dependency and Packaging Risks

## What Is It?

Python's packaging ecosystem (PyPI, pip) makes it easy to add powerful
libraries — but each dependency brings its own vulnerabilities, licenses, and
maintenance lifecycle into your project. Three related risks compound each other:

**Unpinned versions** — Without explicit version pins, `pip install` installs
the latest available release. A CVE disclosed overnight becomes active on
your next deployment without any code change.

**Dependency confusion** — Build systems that check internal registries first
but fall back to PyPI can be tricked into installing a malicious public package
with a name that collides with an internal one. Attackers have exploited this
to achieve RCE inside corporate build environments.

**Typosquatting** — Packages with names one keystroke away from popular
libraries are routinely published to PyPI. `reqeusts`, `Flaskk`, `pil1ow` have
all existed as malicious packages at various times.

**Transitive dependencies** — Your `requirements.txt` may list 5 packages, but
`pip` may install 40+. Each transitive dependency carries its own CVE history
and is often not reviewed or tracked by developers.

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/requirements.txt` | Unpinned deps; `Pillow==9.0.0` (CVE-2022-22817); no hashes |
| `vulnerable/app.py` | Flask app that uses the dependencies |
| `fixed/requirements.in` | Human-maintained source constraints |
| `fixed/requirements.txt` | `pip-compile` lock file — all deps pinned with SHA-256 hashes |
| `fixed/pip.conf` | Restricts installation to a trusted internal mirror |
| `fixed/audit.sh` | CI gate: fails build if `pip-audit` finds any CVE |
| `fixed/app.py` | Same app — packaging is the only change |

## How to Run

### Prerequisites

```bash
pip install pip-audit pip-tools
```

---

### Vulnerable Version — CVE Detected

```bash
cd vulnerable
pip install -r requirements.txt
pip-audit -r requirements.txt
```

Expected `pip-audit` output (abridged):

```
Name    Version ID                  Fix Versions
------- ------- ------------------- ------------
Pillow  9.0.0   GHSA-8vj2-vxx3-667w 9.0.1
                CVE-2022-22817      ...

1 vulnerability found
```

The vulnerable `Pillow==9.0.0` is flagged. The unpinned packages (flask,
requests, pyyaml) may also surface CVEs depending on what pip resolves to.

---

### Fixed Version — Clean Audit

```bash
cd fixed

# Install with hash verification — pip rejects any package with a non-matching hash
pip install --require-hashes -r requirements.txt

# Run the CVE scan
./audit.sh
```

Expected output:

```
=== Dependency Vulnerability Audit ===
Scanning: requirements.txt

No known vulnerabilities found
PASS: No known vulnerabilities detected.
```

Pillow is now `10.3.0` (not vulnerable). All transitive deps are pinned.
Hash verification ensures the installed packages are byte-for-byte identical
to what was audited — a tampered PyPI package or a man-in-the-middle substitution
would produce a hash mismatch and abort the install.

---

### Regenerating the Lock File

After updating `requirements.in`:

```bash
pip-compile --generate-hashes --output-file requirements.txt requirements.in
```

Commit both files. CI always installs from `requirements.txt` (never `requirements.in`).

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Version pinning | Unpinned (`flask`, `requests`, `pyyaml`) | All packages pinned to exact versions via pip-compile |
| Known CVE | `Pillow==9.0.0` (CVE-2022-22817) | `Pillow==10.3.0` — no known CVEs |
| Transitive dependencies | Untracked | All transitive deps enumerated and pinned in lock file |
| Integrity verification | None | SHA-256 hashes for every package; `--require-hashes` enforced |
| Registry control | Public PyPI only | `pip.conf` routes to internal mirror; PyPI fallback disabled |
| CI gate | None | `audit.sh` runs `pip-audit`; pipeline fails on CVE detection |

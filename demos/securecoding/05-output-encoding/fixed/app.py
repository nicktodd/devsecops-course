"""
Contextual Output Encoding — Fixed

The same mission notes board with two XSS vectors closed:

  1. HTML context — the '| safe' filter is removed. Jinja2's default
     auto-escaping for .html templates converts < > & " ' to their HTML
     entities, so script tags are rendered as visible text, not as markup.

  2. JavaScript context — the note value is encoded with '| tojson',
     which produces a properly quoted and escaped JSON string literal.
     Closing quotes and special characters are escaped, so the string
     boundary cannot be broken by attacker-supplied input.

The application code is unchanged from vulnerable/app.py — the XSS
fixes are entirely in the template.

Run:
    pip install flask
    python app.py

Verify XSS is no longer possible:

    Note text: <script>alert('XSS via HTML context')</script>
    # Rendered as: &lt;script&gt;alert(...)&lt;/script&gt; — visible text, not code

    Note text: '; alert('XSS via JS context'); var x='
    # Rendered as: "'; alert('XSS via JS context'); var x='"
    # The single quotes are JSON-escaped; the string boundary is intact
"""

from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)

notes: list[str] = []


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", notes=notes)


@app.route("/note", methods=["POST"])
def add_note():
    note = request.form.get("note", "")
    notes.append(note)
    return redirect(url_for("index"))


if __name__ == "__main__":
    # FIX: debug=False — never expose interactive tracebacks in production
    app.run(debug=False)

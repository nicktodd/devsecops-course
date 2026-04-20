"""
OWASP A03:2021 - Injection
Fix: Parameterised queries (prepared statements) ensure user input is
always treated as data, never as executable SQL syntax.

Run:
    pip install flask
    python app.py

Verify injection no longer works:
    # Attempted bypass — now returns 401 (invalid credentials) instead of granting access
    curl "http://127.0.0.1:5000/login?username=' OR '1'='1' --&password=anything"

    # Legitimate login
    curl "http://127.0.0.1:5000/login?username=alice&password=secret"
"""

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB = "users.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users
        (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)
    """)
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'alice', 'secret', 'user')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'admin', 'adminpass', 'admin')")
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # FIX: Use parameterised queries. The ? placeholders are filled by the
    # database driver, which escapes and quotes the values safely.
    # User input is passed as a separate tuple — it is NEVER concatenated into the SQL string.
    # Injected SQL syntax (e.g. ' OR '1'='1') is treated as a literal string value,
    # not as SQL code, so it can never match a real username.
    query = "SELECT id, username, role FROM users WHERE username=? AND password=?"

    conn = sqlite3.connect(DB)
    try:
        # SAFE: the database driver handles all escaping
        result = conn.execute(query, (username, password)).fetchone()
    except sqlite3.OperationalError as e:
        # FIX: Return a generic error — do not leak database details to the client
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

    if result:
        # FIX: Return only the role from the parameterised query result.
        # The password field is excluded from the SELECT so it is never in memory here.
        return jsonify({"logged_in": True, "role": result[2]}), 200
    return jsonify({"logged_in": False}), 401


if __name__ == "__main__":
    init_db()
    # FIX: debug=False — never expose the Werkzeug debugger in production
    app.run(debug=False)

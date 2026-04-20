"""
OWASP A01:2021 - Broken Access Control
Vulnerability: Insecure Direct Object Reference (IDOR)

A user can change the user_id in the URL to read any other user's
sensitive data. There is no server-side check that the authenticated
user is only accessing their own record.

Run:
    pip install flask
    python app.py
Exploit:
    # Log in as user 1 (alice), then request user 2's data:
    curl -H "X-User-Id: 1" http://127.0.0.1:5000/user/2
    # Returns bob's SSN and email — data alice should never see.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

# Simulated database of users (including sensitive fields)
users = {
    1: {"id": 1, "username": "alice", "email": "alice@example.com", "ssn": "123-45-6789"},
    2: {"id": 2, "username": "bob",   "email": "bob@example.com",   "ssn": "987-65-4321"},
    3: {"id": 3, "username": "carol", "email": "carol@example.com", "ssn": "555-12-3456"},
}


@app.route("/user/<int:user_id>", methods=["GET"])
def get_user(user_id):
    # VULNERABILITY: The X-User-Id header is accepted at face value from the client.
    # It is never cryptographically verified, so any client can forge any identity.
    current_user = request.headers.get("X-User-Id")  # VULNERABLE: header is client-controlled

    # VULNERABILITY: There is no check that current_user == user_id.
    # Any value of user_id in the URL is accepted, giving access to any account.
    # This is a classic Insecure Direct Object Reference (IDOR).
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # VULNERABILITY: The entire user object is returned, including the sensitive SSN field.
    return jsonify(user), 200


if __name__ == "__main__":
    # VULNERABILITY: debug=True exposes an interactive debugger on unhandled exceptions.
    app.run(debug=True)

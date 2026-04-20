"""
OWASP A01:2021 - Broken Access Control
Fix: Enforce ownership checks using a signed JWT so users can only
access their own records. Sensitive fields are excluded from the response.

Run:
    pip install flask pyjwt
    python app.py

Generate a test token (run in Python):
    import jwt
    print(jwt.encode({"user_id": 1}, "change-me-in-production", algorithm="HS256"))

Test (authorised — own record):
    curl -H "Authorization: Bearer <token_for_user_1>" http://127.0.0.1:5000/user/1

Test (forbidden — another user's record):
    curl -H "Authorization: Bearer <token_for_user_1>" http://127.0.0.1:5000/user/2
    # Returns 403 Forbidden
"""

from flask import Flask, request, jsonify, abort
import jwt

app = Flask(__name__)

# In production: load from environment variable, never hard-code.
SECRET_KEY = "change-me-in-production"

users = {
    1: {"id": 1, "username": "alice", "email": "alice@example.com", "ssn": "123-45-6789"},
    2: {"id": 2, "username": "bob",   "email": "bob@example.com",   "ssn": "987-65-4321"},
    3: {"id": 3, "username": "carol", "email": "carol@example.com", "ssn": "555-12-3456"},
}


def get_current_user_id():
    """Extract and verify user identity from a signed JWT.
    Aborts with 401 if the token is missing or invalid.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")
    try:
        # FIX: Token is cryptographically verified — the server controls the SECRET_KEY.
        # The client cannot forge or tamper with the user_id claim.
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.InvalidTokenError:
        abort(401)


@app.route("/user/<int:user_id>", methods=["GET"])
def get_user(user_id):
    current_user_id = get_current_user_id()

    # FIX: Server-side ownership check — a user can only retrieve their own record.
    # Privilege escalation (e.g. admin access) would require an explicit role check here.
    if current_user_id != user_id:
        abort(403)

    user = users.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # FIX: Return only the fields the caller is allowed to see.
    # Sensitive fields such as SSN are excluded from the response.
    safe_user = {"id": user["id"], "username": user["username"], "email": user["email"]}
    return jsonify(safe_user), 200


if __name__ == "__main__":
    # FIX: debug=False in production — never expose the Werkzeug debugger.
    app.run(debug=False)

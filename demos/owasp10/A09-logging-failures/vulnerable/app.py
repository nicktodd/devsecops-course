"""
OWASP A09:2021 - Security Logging and Monitoring Failures

Three vulnerability patterns demonstrated:
  1. Sensitive data (passwords, tokens, API keys) written to logs in plaintext
  2. Silent exception swallowing — errors are hidden from operators
  3. Failed authentication events are not logged — brute-force is undetectable

Run:
    pip install flask
    python app.py

Then trigger each endpoint and observe what appears in the console output.
"""

import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY: Root logger configured at DEBUG level.
# Every debug() call throughout the application — including those that log
# passwords and tokens — will be written to stdout/log files.
logging.basicConfig(
    level=logging.DEBUG,  # VULNERABLE: DEBUG emits everything
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    # VULNERABILITY: The user's plaintext password is written to the log.
    # Any developer, sysadmin, log aggregator (Splunk, ELK, CloudWatch), or
    # attacker who gains read access to logs immediately has the user's password.
    logger.debug(f"Login attempt: username={username}, password={password}")  # VULNERABLE

    if username == "alice" and password == "secret":
        session_token = "tok_abc123xyz"  # In a real app: generated securely per session

        # VULNERABILITY: Session token logged in plaintext.
        # Anyone who can read the logs can replay this token to hijack the session.
        logger.info(f"Login successful for {username}. Token: {session_token}")  # VULNERABLE

        return jsonify({"token": session_token}), 200

    # VULNERABILITY: Failed authentication is NOT logged.
    # An attacker running a brute-force or credential-stuffing attack generates
    # no observable signal — monitoring systems cannot raise an alert.
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/transfer", methods=["POST"])
def transfer():
    try:
        amount     = request.json.get("amount", 0)
        to_account = request.json.get("to_account", "")
        api_key    = request.headers.get("X-API-Key", "")

        # VULNERABILITY: The full API key is written to the log.
        # An attacker who compromises the log system can extract live API keys
        # and use them to make authenticated requests.
        logger.debug(f"Transfer: amount={amount}, to={to_account}, api_key={api_key}")  # VULNERABLE

        # ... perform transfer logic ...
        return jsonify({"status": "ok"}), 200

    except Exception:
        # VULNERABILITY: All exceptions are silently swallowed.
        # Operators cannot detect errors, and attackers probing the system
        # receive a misleading 200 OK response even when something went wrong.
        pass  # VULNERABLE: silent swallow — no log, no metric, no alert

    # VULNERABILITY: Returns 200 OK even when an exception was caught.
    # This masks application failures and makes monitoring impossible.
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    # VULNERABILITY: debug=True — Flask's interactive debugger is exposed
    app.run(debug=True)

"""
OWASP A09:2021 - Security Logging and Monitoring Failures
Fix:
  1. Sensitive values are masked before logging — passwords and tokens are never written
  2. Exceptions are caught, logged with a full traceback, and return a proper 500 response
  3. Every failed authentication generates a WARNING log with IP address for alerting

Run:
    pip install flask
    python app.py
"""

import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

# FIX: Production log level is INFO — DEBUG messages (which tend to carry the
# most sensitive data) are suppressed unless explicitly enabled during debugging.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
logger = logging.getLogger(__name__)


def mask(value: str, visible: int = 4) -> str:
    """Return a masked version of a sensitive string safe for logging.

    Example: mask("tok_abc123xyz") -> "tok_***"
    """
    if not value:
        return "(empty)"
    if len(value) <= visible:
        return "***"
    return value[:visible] + "***"


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    # FIX: Log the security event (username, IP) but NEVER the password value.
    # Logging the username is acceptable for audit trails; logging the password is not.
    logger.info(
        "Login attempt | user=%s | ip=%s",
        username,
        request.remote_addr
    )

    if username == "alice" and password == "secret":
        session_token = "tok_abc123xyz"

        # FIX: Log that the login succeeded. Do NOT log the token value.
        # The token is a credential — treat it with the same care as a password.
        logger.info("Login successful | user=%s | ip=%s", username, request.remote_addr)

        return jsonify({"token": session_token}), 200

    # FIX: Log failed authentication as a WARNING with enough context to trigger
    # an alert in a SIEM or monitoring system (e.g. CloudWatch alarm on
    # "N WARNING login failures from the same IP in 60 seconds").
    logger.warning(
        "Failed login | user=%s | ip=%s",
        username,
        request.remote_addr
    )
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/transfer", methods=["POST"])
def transfer():
    try:
        amount     = request.json.get("amount", 0)
        to_account = request.json.get("to_account", "")
        api_key    = request.headers.get("X-API-Key", "")

        # FIX: Log a masked version of the API key for correlation purposes.
        # The first 4 characters are enough to identify the key family in an audit;
        # the rest are hidden so the log entry cannot be used to replay the key.
        logger.info(
            "Transfer initiated | amount=%s | to=%s | key_prefix=%s",
            amount,
            to_account,
            mask(api_key)
        )

        # ... perform transfer logic ...
        return jsonify({"status": "ok"}), 200

    except Exception as exc:
        # FIX: Log the exception with a full stack trace so the root cause can be
        # diagnosed. exc_info=True captures the current exception information.
        logger.error("Transfer failed with unexpected error | error=%s", exc, exc_info=True)

        # FIX: Return a 500 Internal Server Error — not a misleading 200 OK.
        # This allows load balancers, monitors, and clients to detect failures.
        return jsonify({"status": "error", "message": "Internal server error"}), 500


if __name__ == "__main__":
    # FIX: debug=False in production
    app.run(debug=False)

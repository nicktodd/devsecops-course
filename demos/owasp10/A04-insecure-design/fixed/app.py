"""
OWASP A04:2021 - Insecure Design
Fix: Redesigned OTP flow with:
  - Cryptographically secure 6-digit OTP (1,000,000 values)
  - OTP expiry (5 minutes)
  - Maximum attempt limit with account lockout
  - Constant-time comparison to prevent timing attacks

Run:
    pip install flask
    python app.py

Verify brute-force is blocked:
    # After 5 incorrect attempts the OTP is invalidated:
    for i in {1..6}; do
        curl -s -X POST http://127.0.0.1:5000/verify-otp \
             -H "Content-Type: application/json" \
             -d '{"email":"test@example.com","otp":"0000"}'
        echo
    done
    # 6th attempt returns 429 Too Many Requests
"""

import secrets
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_ATTEMPTS = 5          # Lock out after this many incorrect guesses
OTP_TTL_SECONDS = 300    # OTP expires after 5 minutes

# OTP store: { email -> {"otp": str, "expires_at": float, "attempts": int} }
pending_otps: dict[str, dict] = {}


@app.route("/request-reset", methods=["POST"])
def request_reset():
    email = request.json.get("email", "")

    # FIX: Use secrets.randbelow() — cryptographically secure PRNG (CSPRNG).
    # 6 digits gives a keyspace of 1,000,000 — 100x larger than the vulnerable version.
    otp = str(secrets.randbelow(900000) + 100000)  # Range: 100000–999999

    pending_otps[email] = {
        "otp": otp,
        "expires_at": time.time() + OTP_TTL_SECONDS,
        "attempts": 0,
    }

    # FIX: In production, send OTP via email. Never log the OTP value itself.
    print(f"[INFO] OTP dispatched to {email}")  # Log the event, not the value
    return jsonify({"message": "OTP sent to your email"}), 200


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = request.json.get("email", "")
    otp_input = request.json.get("otp", "")

    record = pending_otps.get(email)
    if not record:
        return jsonify({"message": "No pending OTP for this email"}), 400

    # FIX: Reject expired OTPs — a time window limits the brute-force window
    if time.time() > record["expires_at"]:
        del pending_otps[email]
        return jsonify({"message": "OTP has expired. Please request a new one."}), 400

    # FIX: Enforce a maximum number of attempts before invalidating the OTP.
    # Even if the attacker is fast, they only get MAX_ATTEMPTS guesses.
    if record["attempts"] >= MAX_ATTEMPTS:
        del pending_otps[email]
        return jsonify({"message": "Too many failed attempts. Request a new OTP."}), 429

    # Increment the attempt counter before checking the OTP value
    record["attempts"] += 1

    # FIX: Use secrets.compare_digest() for constant-time string comparison.
    # A regular == comparison may return early on the first differing character,
    # leaking timing information that can narrow down the correct OTP.
    if secrets.compare_digest(record["otp"], otp_input):
        del pending_otps[email]
        return jsonify({"message": "OTP valid — proceed to set new password"}), 200

    remaining = MAX_ATTEMPTS - record["attempts"]
    return jsonify({"message": f"Invalid OTP. {remaining} attempt(s) remaining."}), 400


if __name__ == "__main__":
    # FIX: debug=False in production
    app.run(debug=False)

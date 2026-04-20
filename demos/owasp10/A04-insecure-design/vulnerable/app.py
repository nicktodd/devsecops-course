"""
OWASP A04:2021 - Insecure Design
Vulnerability: Password reset OTP with no rate limiting, no expiry,
and a small brute-forceable keyspace.

The design itself is flawed — security controls were not considered
when the feature was architected. This cannot be fixed by sanitising
inputs alone; the entire flow needs to be redesigned.

Run:
    pip install flask
    python app.py

Exploit — brute-force the OTP:
    python brute_force.py
    (See brute_force.py in this directory)
"""

import random
from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory OTP store: { email -> otp_string }
pending_otps: dict[str, str] = {}


@app.route("/request-reset", methods=["POST"])
def request_reset():
    email = request.json.get("email", "")

    # VULNERABILITY: OTP is only 4 digits — a keyspace of just 10,000 values.
    # An automated script can try all combinations in seconds.
    otp = str(random.randint(1000, 9999))  # VULNERABLE: tiny keyspace

    # VULNERABILITY: random.randint uses the Mersenne Twister PRNG, which is not
    # cryptographically secure. With enough observed outputs, the internal state
    # (and therefore future OTPs) can be reconstructed.
    pending_otps[email] = otp

    # In a real application this would be emailed — shown here for demo purposes only
    print(f"[DEBUG] OTP for {email}: {otp}")
    return jsonify({"message": "OTP sent to your email"}), 200


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = request.json.get("email", "")
    otp = request.json.get("otp", "")

    # VULNERABILITY: No rate limiting — an attacker can submit thousands of guesses
    # per second with no delay, lockout, or CAPTCHA challenge.

    # VULNERABILITY: No OTP expiry — an OTP requested days ago is still valid.

    # VULNERABILITY: No attempt counter — there is no limit on the number of
    # incorrect guesses before the OTP is invalidated.

    # Brute-force window: 10,000 guesses / (unlimited req/s) = seconds to crack.

    if pending_otps.get(email) == otp:
        del pending_otps[email]
        return jsonify({"message": "OTP valid — proceed to set new password"}), 200

    # VULNERABILITY: Failed attempts are silently ignored — no counter, no log entry.
    return jsonify({"message": "Invalid OTP"}), 400


if __name__ == "__main__":
    # VULNERABILITY: debug=True leaks internal state to anyone who triggers an error
    app.run(debug=True)

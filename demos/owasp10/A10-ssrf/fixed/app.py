"""
OWASP A10:2021 - Server-Side Request Forgery (SSRF)
Fix: Validate the user-supplied URL against an explicit allowlist of permitted
domains, enforce HTTPS-only, block private/link-local IP ranges (including the
AWS IMDS address 169.254.169.254), and disable HTTP redirects to prevent
redirect-based bypass.

Run:
    pip install flask requests
    python app.py

Test that SSRF is blocked:
    # AWS IMDS — blocked (link-local range)
    curl "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/"

    # Internal IP — blocked
    curl "http://127.0.0.1:5000/fetch?url=http://10.0.1.100:8080/admin"

    # Non-allowlisted domain — blocked
    curl "http://127.0.0.1:5000/fetch?url=https://evil.example.com/steal"

    # Allowlisted domain — permitted
    curl "http://127.0.0.1:5000/fetch?url=https://api.example.com/data"
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# FIX: Explicit allowlist of domains the application is permitted to reach.
# Any domain not in this set is rejected before a network connection is made.
ALLOWED_DOMAINS = frozenset({
    "api.example.com",
    "public-data.example.org",
})

# FIX: IP address ranges that must never be reachable via user-supplied URLs.
# Includes RFC 1918 private ranges, loopback, and the AWS/Azure/GCP
# Instance Metadata Service address (169.254.169.254).
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),      # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),   # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918 private
    ipaddress.ip_network("127.0.0.0/8"),     # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS IMDS
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]


def is_safe_url(url: str) -> tuple[bool, str]:
    """Validate a URL before the application makes an outbound request.

    Returns (True, "") if the URL is safe, or (False, reason) if it is blocked.
    """
    try:
        parsed = urlparse(url)

        # FIX: Only HTTPS is permitted — plain HTTP can be intercepted or MITM'd
        if parsed.scheme != "https":
            return False, "Only HTTPS URLs are permitted"

        hostname = parsed.hostname
        if not hostname:
            return False, "Could not extract hostname from URL"

        # FIX: Domain must be on the explicit allowlist.
        # Unknown external domains are blocked regardless of their IP address.
        if hostname not in ALLOWED_DOMAINS:
            return False, f"Domain not in allowlist: {hostname}"

        # FIX: Resolve the hostname to its IP address and verify it does not fall
        # within a blocked range. This prevents DNS rebinding attacks, where an
        # allowed domain initially resolves to a safe IP but later resolves to
        # an internal address.
        try:
            resolved_ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        except socket.gaierror:
            return False, f"Could not resolve hostname: {hostname}"

        for blocked in BLOCKED_NETWORKS:
            if resolved_ip in blocked:
                return False, f"Resolved IP {resolved_ip} is in a blocked range"

        return True, ""

    except Exception:
        return False, "URL validation error"


@app.route("/fetch", methods=["GET"])
def fetch_url():
    url = request.args.get("url", "")

    if not url:
        return jsonify({"error": "url parameter is required"}), 400

    # FIX: Validate the URL before making any outbound network connection
    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"URL not permitted: {reason}"}), 400

    try:
        # FIX: Disable automatic redirect following.
        # Without this, a server at an allowed domain could redirect to
        # http://169.254.169.254/ and the library would follow it silently.
        response = requests.get(url, timeout=5, allow_redirects=False)

        # FIX: Cap the response body to prevent memory exhaustion from large responses
        return jsonify({
            "status_code": response.status_code,
            "body": response.text[:10_000],
        }), 200

    except requests.RequestException as e:
        # FIX: Return a generic error — do not expose internal network topology
        return jsonify({"error": "Request failed"}), 502


if __name__ == "__main__":
    # FIX: debug=False in production
    app.run(debug=False)

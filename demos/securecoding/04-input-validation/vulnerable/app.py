"""
Input Validation Fundamentals — Vulnerable

A satellite command dispatch endpoint that accepts a JSON payload
but performs no validation before acting on the data.

Vulnerabilities demonstrated:
  1. No type enforcement — altitude accepted as a string, list, or anything else
  2. No range validation — negative altitude or values above 36,000 km accepted
  3. No length limit — arbitrarily long command_name accepted
  4. No format check on target_id — any string accepted
  5. Missing/extra fields cause unhandled exceptions whose tracebacks are
     returned verbatim to the caller, leaking internal file paths and structure

Run:
    pip install flask
    python app.py

Exploit examples:

    # Wrong type for altitude — breaks downstream arithmetic silently
    curl -s -X POST http://127.0.0.1:5000/command \\
        -H "Content-Type: application/json" \\
        -d '{"command_name":"ORBIT_ADJUST","altitude_km":"high","target_id":"SAT-0001"}'

    # Out-of-range altitude — negative orbit accepted without error
    curl -s -X POST http://127.0.0.1:5000/command \\
        -H "Content-Type: application/json" \\
        -d '{"command_name":"ORBIT_ADJUST","altitude_km":-500,"target_id":"SAT-0001"}'

    # Missing required field — returns a Python KeyError traceback (leaks internals)
    curl -s -X POST http://127.0.0.1:5000/command \\
        -H "Content-Type: application/json" \\
        -d '{"command_name":"ORBIT_ADJUST"}'

    # Oversized command_name — no length limit enforced
    curl -s -X POST http://127.0.0.1:5000/command \\
        -H "Content-Type: application/json" \\
        -d '{"command_name":"'$(python3 -c "print('A'*10000)")'","altitude_km":400,"target_id":"SAT-0001"}'
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/command", methods=["POST"])
def send_command():
    data = request.get_json()

    # VULNERABILITY: No check that 'data' is not None (malformed or missing Content-Type).
    # VULNERABILITY: dict key access raises KeyError on missing fields — the unhandled
    #                exception returns a full Python traceback to the caller, leaking
    #                internal paths, module names, and application structure.
    command_name = data["command_name"]      # VULNERABLE: no length or format check
    altitude_km  = data["altitude_km"]       # VULNERABLE: no type or range check
    target_id    = data["target_id"]         # VULNERABLE: no format check

    # VULNERABILITY: altitude_km could be a string, list, dict, or negative number.
    #                Downstream arithmetic on an unexpected type causes silent errors
    #                or unhandled exceptions that may reveal stack traces.
    burn_duration = altitude_km * 0.42       # VULNERABLE: type not enforced

    result = {
        "status":        "dispatched",
        "command":       command_name,
        "target":        target_id,
        "altitude_km":   altitude_km,
        "burn_duration": burn_duration,
    }
    return jsonify(result), 202


if __name__ == "__main__":
    # VULNERABILITY: debug=True returns interactive tracebacks in the browser
    app.run(debug=True)

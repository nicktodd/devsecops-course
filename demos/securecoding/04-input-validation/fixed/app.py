"""
Input Validation Fundamentals — Fixed

The same satellite command dispatch endpoint, now validated with Pydantic v2.

Fixes applied:
  1. Pydantic model declares the exact expected type for every field
  2. altitude_km is constrained to the valid Low Earth Orbit — GEO range (200–36,000 km)
  3. command_name is limited to 32 uppercase letters and underscores via regex
  4. target_id is constrained to the SAT-NNNN format
  5. extra='forbid' rejects any unexpected fields in the request body
  6. Validation errors return a generic 400 with field-level messages —
     no internal paths, module names, or stack frames are exposed

The validation schema acts as an allowlist: any input that does not
conform to the declared type, range, length, and format is rejected
before it reaches business logic.

Run:
    pip install flask pydantic
    python app.py

Verify rejection of invalid input:

    # Wrong type — rejected with 400
    curl -s -X POST http://127.0.0.1:5000/command \\
        -H "Content-Type: application/json" \\
        -d '{"command_name":"ORBIT_ADJUST","altitude_km":"high","target_id":"SAT-0001"}'
    # {"errors": [{"field": "altitude_km", "message": "Input should be a valid integer"}]}

    # Out-of-range altitude — rejected
    curl -s -X POST http://127.0.0.1:5000/command \\
        -H "Content-Type: application/json" \\
        -d '{"command_name":"ORBIT_ADJUST","altitude_km":-500,"target_id":"SAT-0001"}'
    # {"errors": [{"field": "altitude_km", "message": "Input should be greater than or equal to 200"}]}

    # Invalid target_id format — rejected
    curl -s -X POST http://127.0.0.1:5000/command \\
        -H "Content-Type: application/json" \\
        -d '{"command_name":"ORBIT_ADJUST","altitude_km":400,"target_id":"EVIL;DROP"}'
    # {"errors": [{"field": "target_id", ...}]}

    # Valid request
    curl -s -X POST http://127.0.0.1:5000/command \\
        -H "Content-Type: application/json" \\
        -d '{"command_name":"ORBIT_ADJUST","altitude_km":400,"target_id":"SAT-0042"}'
    # {"status": "dispatched", ...}
"""

from typing import Annotated

from flask import Flask, jsonify, request
from pydantic import BaseModel, Field, ValidationError

app = Flask(__name__)


# FIX: Pydantic model acts as an explicit allowlist schema.
# Each field declares its acceptable type, format, length, and range.
# Any input that does not match is rejected before reaching business logic.
class SatelliteCommand(BaseModel):
    model_config = {"extra": "forbid"}  # FIX: reject unexpected fields

    # FIX: command_name must be 1–32 uppercase letters and underscores only.
    #      Regex allowlist — everything else is rejected.
    command_name: Annotated[
        str,
        Field(min_length=1, max_length=32, pattern=r"^[A-Z_]+$"),
    ]

    # FIX: altitude_km must be an integer in the valid orbital range.
    #      200 km = minimum stable LEO; 36,000 km = geostationary orbit.
    altitude_km: Annotated[
        int,
        Field(ge=200, le=36_000),
    ]

    # FIX: target_id must match the SAT-NNNN format exactly.
    target_id: Annotated[
        str,
        Field(pattern=r"^SAT-\d{4}$"),
    ]


@app.route("/command", methods=["POST"])
def send_command():
    # FIX: Validate Content-Type and parse JSON safely.
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    raw = request.get_json(silent=True)
    if raw is None:
        return jsonify({"error": "Invalid JSON body"}), 400

    # FIX: Validate at the system boundary — before any business logic.
    # ValidationError carries field-level details but no internal paths.
    try:
        cmd = SatelliteCommand.model_validate(raw)
    except ValidationError as exc:
        # FIX: Return structured field errors; no stack trace, no internals.
        errors = [
            {"field": ".".join(str(loc) for loc in err["loc"]), "message": err["msg"]}
            for err in exc.errors()
        ]
        return jsonify({"errors": errors}), 400

    # Business logic only runs after all fields have been validated.
    burn_duration = cmd.altitude_km * 0.42

    return jsonify({
        "status":        "dispatched",
        "command":       cmd.command_name,
        "target":        cmd.target_id,
        "altitude_km":   cmd.altitude_km,
        "burn_duration": burn_duration,
    }), 202


if __name__ == "__main__":
    # FIX: debug=False — never expose interactive tracebacks in production
    app.run(debug=False)

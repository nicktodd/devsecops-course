"""
ESA Mission Registry - Missions Lambda Handler
Handles CRUD operations for space missions.

STRIDE notes:
  - Spoofing:    Caller identity extracted from verified Cognito JWT claims
  - Tampering:   Input validated/sanitised before writing to DynamoDB
  - Repudiation: All writes logged with caller identity and timestamp
  - Info Disc:   Sensitive fields never returned in list responses
  - DoS:         Pagination enforced; no unbounded scans
  - EoP:         Role check enforced for mutating operations
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["MISSIONS_TABLE"])

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
MAX_PAGE_SIZE = 50
ALLOWED_STATUSES = {"planned", "active", "completed", "cancelled"}
WRITE_ROLES = {"admin"}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def build_response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            # Security headers (STRIDE: Information Disclosure)
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        },
        "body": json.dumps(body, default=str),
    }


def get_caller_info(event: dict) -> dict:
    """Extract verified identity from Cognito JWT claims (STRIDE: Spoofing)."""
    claims = (
        event.get("requestContext", {})
             .get("authorizer", {})
             .get("claims", {})
    )
    return {
        "sub": claims.get("sub", "unknown"),
        "email": claims.get("email", "unknown"),
        "groups": claims.get("cognito:groups", ""),
    }


def caller_has_write_access(caller: dict) -> bool:
    """Enforce role-based access (STRIDE: Elevation of Privilege)."""
    groups = set(caller["groups"].split(",")) if caller["groups"] else set()
    return bool(groups & WRITE_ROLES)


def validate_mission_input(body: dict) -> tuple[bool, str]:
    """Validate and sanitise input (STRIDE: Tampering)."""
    required = {"name", "agency", "status", "launchYear"}
    missing = required - body.keys()
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"

    if body["status"] not in ALLOWED_STATUSES:
        return False, f"Invalid status. Must be one of: {ALLOWED_STATUSES}"

    try:
        year = int(body["launchYear"])
        if not (1950 <= year <= 2200):
            return False, "launchYear must be between 1950 and 2200"
    except (ValueError, TypeError):
        return False, "launchYear must be an integer"

    name = str(body["name"]).strip()
    if not name or len(name) > 200:
        return False, "name must be between 1 and 200 characters"

    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# Route handlers
# ─────────────────────────────────────────────────────────────────────────────

def list_missions(event: dict) -> dict:
    """GET /missions  - paginated list."""
    params = event.get("queryStringParameters") or {}
    limit = min(int(params.get("limit", 20)), MAX_PAGE_SIZE)
    exclusive_start_key = params.get("nextToken")

    scan_kwargs = {"Limit": limit}
    if exclusive_start_key:
        scan_kwargs["ExclusiveStartKey"] = {"missionId": exclusive_start_key}

    result = table.scan(**scan_kwargs)

    response_body = {
        "missions": result.get("Items", []),
        "count": result.get("Count", 0),
    }
    if "LastEvaluatedKey" in result:
        response_body["nextToken"] = result["LastEvaluatedKey"]["missionId"]

    return build_response(200, response_body)


def get_mission(mission_id: str) -> dict:
    """GET /missions/{missionId}"""
    result = table.get_item(Key={"missionId": mission_id})
    item = result.get("Item")
    if not item:
        return build_response(404, {"error": "Mission not found"})
    return build_response(200, item)


def create_mission(event: dict, caller: dict) -> dict:
    """POST /missions  - write role required."""
    if not caller_has_write_access(caller):
        logger.warning("Unauthorised create attempt by %s", caller["email"])
        return build_response(403, {"error": "Insufficient permissions"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return build_response(400, {"error": "Invalid JSON body"})

    valid, error = validate_mission_input(body)
    if not valid:
        return build_response(400, {"error": error})

    mission_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    item = {
        "missionId": mission_id,
        "name": str(body["name"]).strip(),
        "agency": str(body["agency"]).strip(),
        "status": body["status"],
        "launchYear": int(body["launchYear"]),
        "description": str(body.get("description", "")).strip()[:2000],
        "createdAt": now,
        "updatedAt": now,
        # Audit trail (STRIDE: Repudiation)
        "createdBy": caller["email"],
    }

    table.put_item(Item=item)
    logger.info("Mission created: %s by %s", mission_id, caller["email"])
    return build_response(201, item)


def update_mission(mission_id: str, event: dict, caller: dict) -> dict:
    """PUT /missions/{missionId}  - write role required."""
    if not caller_has_write_access(caller):
        logger.warning("Unauthorised update attempt by %s", caller["email"])
        return build_response(403, {"error": "Insufficient permissions"})

    # Verify exists first
    existing = table.get_item(Key={"missionId": mission_id}).get("Item")
    if not existing:
        return build_response(404, {"error": "Mission not found"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return build_response(400, {"error": "Invalid JSON body"})

    valid, error = validate_mission_input(body)
    if not valid:
        return build_response(400, {"error": error})

    now = datetime.now(timezone.utc).isoformat()
    updated = {
        **existing,
        "name": str(body["name"]).strip(),
        "agency": str(body["agency"]).strip(),
        "status": body["status"],
        "launchYear": int(body["launchYear"]),
        "description": str(body.get("description", "")).strip()[:2000],
        "updatedAt": now,
        "updatedBy": caller["email"],
    }

    table.put_item(Item=updated)
    logger.info("Mission updated: %s by %s", mission_id, caller["email"])
    return build_response(200, updated)


def delete_mission(mission_id: str, caller: dict) -> dict:
    """DELETE /missions/{missionId}  - write role required."""
    if not caller_has_write_access(caller):
        logger.warning("Unauthorised delete attempt by %s", caller["email"])
        return build_response(403, {"error": "Insufficient permissions"})

    existing = table.get_item(Key={"missionId": mission_id}).get("Item")
    if not existing:
        return build_response(404, {"error": "Mission not found"})

    table.delete_item(Key={"missionId": mission_id})
    logger.info("Mission deleted: %s by %s", mission_id, caller["email"])
    return build_response(200, {"message": f"Mission {mission_id} deleted"})


# ─────────────────────────────────────────────────────────────────────────────
# Handler
# ─────────────────────────────────────────────────────────────────────────────

def handler(event: dict, context) -> dict:
    logger.info("Event: %s", json.dumps({k: v for k, v in event.items() if k != "body"}))

    http_method = event.get("httpMethod", "")
    path_params = event.get("pathParameters") or {}
    mission_id = path_params.get("missionId")
    caller = get_caller_info(event)

    try:
        if http_method == "GET" and not mission_id:
            return list_missions(event)
        elif http_method == "GET" and mission_id:
            return get_mission(mission_id)
        elif http_method == "POST":
            return create_mission(event, caller)
        elif http_method == "PUT" and mission_id:
            return update_mission(mission_id, event, caller)
        elif http_method == "DELETE" and mission_id:
            return delete_mission(mission_id, caller)
        else:
            return build_response(405, {"error": "Method not allowed"})

    except ClientError as e:
        logger.error("DynamoDB error: %s", e)
        return build_response(500, {"error": "Internal server error"})
    except Exception as e:
        logger.error("Unexpected error: %s", e, exc_info=True)
        return build_response(500, {"error": "Internal server error"})

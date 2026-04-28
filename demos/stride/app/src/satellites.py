"""
ESA Mission Registry - Satellites Lambda Handler
Handles CRUD for satellites, each linked to a mission.
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
table = dynamodb.Table(os.environ["SATELLITES_TABLE"])

MAX_PAGE_SIZE = 50
WRITE_ROLES = {"admin"}
ALLOWED_TYPES = {"Earth Observation", "Communications", "Navigation", "Science", "Technology Demo"}


def build_response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        },
        "body": json.dumps(body, default=str),
    }


def get_caller_info(event: dict) -> dict:
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
    groups = set(caller["groups"].split(",")) if caller["groups"] else set()
    return bool(groups & WRITE_ROLES)


def validate_satellite_input(body: dict) -> tuple[bool, str]:
    required = {"name", "missionId", "type", "orbitAltitudeKm"}
    missing = required - body.keys()
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"

    if body["type"] not in ALLOWED_TYPES:
        return False, f"Invalid type. Must be one of: {ALLOWED_TYPES}"

    try:
        alt = float(body["orbitAltitudeKm"])
        if not (160 <= alt <= 42500):
            return False, "orbitAltitudeKm must be between 160 and 42500 km"
    except (ValueError, TypeError):
        return False, "orbitAltitudeKm must be a number"

    name = str(body["name"]).strip()
    if not name or len(name) > 200:
        return False, "name must be between 1 and 200 characters"

    return True, ""


def list_satellites(event: dict) -> dict:
    params = event.get("queryStringParameters") or {}
    limit = min(int(params.get("limit", 20)), MAX_PAGE_SIZE)
    exclusive_start_key = params.get("nextToken")

    scan_kwargs = {"Limit": limit}
    if exclusive_start_key:
        scan_kwargs["ExclusiveStartKey"] = {"satelliteId": exclusive_start_key}

    result = table.scan(**scan_kwargs)
    response_body = {"satellites": result.get("Items", []), "count": result.get("Count", 0)}
    if "LastEvaluatedKey" in result:
        response_body["nextToken"] = result["LastEvaluatedKey"]["satelliteId"]
    return build_response(200, response_body)


def get_satellite(satellite_id: str) -> dict:
    result = table.get_item(Key={"satelliteId": satellite_id})
    item = result.get("Item")
    if not item:
        return build_response(404, {"error": "Satellite not found"})
    return build_response(200, item)


def create_satellite(event: dict, caller: dict) -> dict:
    if not caller_has_write_access(caller):
        logger.warning("Unauthorised satellite create attempt by %s", caller["email"])
        return build_response(403, {"error": "Insufficient permissions"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return build_response(400, {"error": "Invalid JSON body"})

    valid, error = validate_satellite_input(body)
    if not valid:
        return build_response(400, {"error": error})

    satellite_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    item = {
        "satelliteId": satellite_id,
        "name": str(body["name"]).strip(),
        "missionId": str(body["missionId"]).strip(),
        "type": body["type"],
        "orbitAltitudeKm": float(body["orbitAltitudeKm"]),
        "massKg": float(body.get("massKg", 0)),
        "createdAt": now,
        "createdBy": caller["email"],
    }

    table.put_item(Item=item)
    logger.info("Satellite created: %s by %s", satellite_id, caller["email"])
    return build_response(201, item)


def handler(event: dict, context) -> dict:
    logger.info("Event: %s", json.dumps({k: v for k, v in event.items() if k != "body"}))

    http_method = event.get("httpMethod", "")
    path_params = event.get("pathParameters") or {}
    satellite_id = path_params.get("satelliteId")
    caller = get_caller_info(event)

    try:
        if http_method == "GET" and not satellite_id:
            return list_satellites(event)
        elif http_method == "GET" and satellite_id:
            return get_satellite(satellite_id)
        elif http_method == "POST":
            return create_satellite(event, caller)
        else:
            return build_response(405, {"error": "Method not allowed"})

    except ClientError as e:
        logger.error("DynamoDB error: %s", e)
        return build_response(500, {"error": "Internal server error"})
    except Exception as e:
        logger.error("Unexpected error: %s", e, exc_info=True)
        return build_response(500, {"error": "Internal server error"})

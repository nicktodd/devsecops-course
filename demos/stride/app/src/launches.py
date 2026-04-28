"""
ESA Mission Registry - Launches Lambda Handler
Handles CRUD for launch events linked to missions and satellites.
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
table = dynamodb.Table(os.environ["LAUNCHES_TABLE"])

MAX_PAGE_SIZE = 50
WRITE_ROLES = {"admin"}
ALLOWED_STATUSES = {"scheduled", "go", "launched", "success", "partial_failure", "failure"}
LAUNCH_SITES = {
    "Kourou, French Guiana",
    "Baikonur Cosmodrome",
    "Vandenberg SFB",
    "Cape Canaveral",
    "Plesetsk Cosmodrome",
    "Jiuquan Satellite Launch Center",
    "Satish Dhawan Space Centre",
}


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


def validate_launch_input(body: dict) -> tuple[bool, str]:
    required = {"missionId", "vehicleName", "launchSite", "scheduledDate", "status"}
    missing = required - body.keys()
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"

    if body["status"] not in ALLOWED_STATUSES:
        return False, f"Invalid status. Must be one of: {ALLOWED_STATUSES}"

    if body["launchSite"] not in LAUNCH_SITES:
        return False, f"Unknown launch site: {body['launchSite']}"

    # Validate ISO date format
    try:
        datetime.fromisoformat(body["scheduledDate"])
    except (ValueError, TypeError):
        return False, "scheduledDate must be a valid ISO 8601 date string"

    return True, ""


def list_launches(event: dict) -> dict:
    params = event.get("queryStringParameters") or {}
    limit = min(int(params.get("limit", 20)), MAX_PAGE_SIZE)
    exclusive_start_key = params.get("nextToken")

    scan_kwargs = {"Limit": limit}
    if exclusive_start_key:
        scan_kwargs["ExclusiveStartKey"] = {"launchId": exclusive_start_key}

    result = table.scan(**scan_kwargs)
    response_body = {"launches": result.get("Items", []), "count": result.get("Count", 0)}
    if "LastEvaluatedKey" in result:
        response_body["nextToken"] = result["LastEvaluatedKey"]["launchId"]
    return build_response(200, response_body)


def get_launch(launch_id: str) -> dict:
    result = table.get_item(Key={"launchId": launch_id})
    item = result.get("Item")
    if not item:
        return build_response(404, {"error": "Launch not found"})
    return build_response(200, item)


def create_launch(event: dict, caller: dict) -> dict:
    if not caller_has_write_access(caller):
        logger.warning("Unauthorised launch create attempt by %s", caller["email"])
        return build_response(403, {"error": "Insufficient permissions"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return build_response(400, {"error": "Invalid JSON body"})

    valid, error = validate_launch_input(body)
    if not valid:
        return build_response(400, {"error": error})

    launch_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    item = {
        "launchId": launch_id,
        "missionId": str(body["missionId"]).strip(),
        "vehicleName": str(body["vehicleName"]).strip(),
        "launchSite": body["launchSite"],
        "scheduledDate": body["scheduledDate"],
        "status": body["status"],
        "notes": str(body.get("notes", "")).strip()[:1000],
        "createdAt": now,
        "createdBy": caller["email"],
    }

    table.put_item(Item=item)
    logger.info("Launch created: %s by %s", launch_id, caller["email"])
    return build_response(201, item)


def handler(event: dict, context) -> dict:
    logger.info("Event: %s", json.dumps({k: v for k, v in event.items() if k != "body"}))

    http_method = event.get("httpMethod", "")
    path_params = event.get("pathParameters") or {}
    launch_id = path_params.get("launchId")
    caller = get_caller_info(event)

    try:
        if http_method == "GET" and not launch_id:
            return list_launches(event)
        elif http_method == "GET" and launch_id:
            return get_launch(launch_id)
        elif http_method == "POST":
            return create_launch(event, caller)
        else:
            return build_response(405, {"error": "Method not allowed"})

    except ClientError as e:
        logger.error("DynamoDB error: %s", e)
        return build_response(500, {"error": "Internal server error"})
    except Exception as e:
        logger.error("Unexpected error: %s", e, exc_info=True)
        return build_response(500, {"error": "Internal server error"})

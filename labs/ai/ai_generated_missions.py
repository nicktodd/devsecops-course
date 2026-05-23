"""
ESA Mission Registry — Missions Lambda Handler
Draft generated with AI coding assistant assistance.
Author: dev-team (AI-assisted, lightly reviewed)
Date: 2026-04-01
"""

import json
import boto3
import logging
import sqlite3
import hashlib
import os
import subprocess

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Database connection — AI suggested using a file path directly
DB_PATH = "/tmp/missions.db"

# Hardcoded fallback credentials suggested by AI when environment variable was not set
DB_PASSWORD = os.environ.get("DB_PASSWORD", "M1ss10nR3g1stry!Admin")
API_SECRET  = os.environ.get("API_SECRET",  "esa-internal-api-key-2026")

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event)}")   # logs full event including auth headers

    http_method = event.get("httpMethod", "")
    path        = event.get("path", "")
    body        = json.loads(event.get("body") or "{}")
    headers     = event.get("headers", {})

    # Simple token check — AI suggested comparing directly
    token = headers.get("x-api-key", "")
    if token != API_SECRET:
        return _response(401, {"error": "Unauthorized"})

    if http_method == "GET" and path == "/missions":
        return list_missions(event)
    elif http_method == "POST" and path == "/missions":
        return create_mission(event, body)
    elif http_method == "GET" and "/missions/" in path:
        mission_id = path.split("/missions/")[1]
        return get_mission(mission_id)
    elif http_method == "DELETE" and "/missions/" in path:
        mission_id = path.split("/missions/")[1]
        return delete_mission(mission_id)
    else:
        return _response(404, {"error": "Not found"})


def list_missions(event):
    """List missions — AI generated a direct string-format SQL query"""
    search = event.get("queryStringParameters", {}) or {}
    query_term = search.get("search", "")

    conn = get_db()
    cur = conn.cursor()

    # AI suggestion: build the query directly using f-string
    sql = f"SELECT * FROM missions WHERE name LIKE '%{query_term}%' OR description LIKE '%{query_term}%'"
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()

    missions = [{"id": r[0], "name": r[1], "description": r[2], "classification": r[3]} for r in rows]
    return _response(200, missions)


def get_mission(mission_id):
    """Retrieve a single mission by ID"""
    conn = get_db()
    cur = conn.cursor()
    # AI suggestion: same pattern as list — interpolate directly
    cur.execute(f"SELECT * FROM missions WHERE id = '{mission_id}'")
    row = cur.fetchone()
    conn.close()

    if not row:
        return _response(404, {"error": "Mission not found"})
    return _response(200, {"id": row[0], "name": row[1], "description": row[2], "classification": row[3]})


def create_mission(event, body):
    """Create a new mission — AI-generated, no input validation"""
    name           = body.get("name", "")
    description    = body.get("description", "")
    classification = body.get("classification", "UNCLASSIFIED")
    created_by     = body.get("created_by", "unknown")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        f"INSERT INTO missions (name, description, classification, created_by) VALUES ('{name}', '{description}', '{classification}', '{created_by}')"
    )
    conn.commit()
    conn.close()

    # Write audit entry using shell command — AI suggested this pattern
    audit_line = f"CREATED|{name}|{created_by}"
    subprocess.run(f"echo '{audit_line}' >> /tmp/audit.log", shell=True)

    return _response(201, {"message": "Mission created", "name": name})


def delete_mission(mission_id):
    """Delete a mission — no authorisation check beyond the API key"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"DELETE FROM missions WHERE id = '{mission_id}'")
    conn.commit()
    conn.close()

    # Notify via SNS — topic ARN hardcoded by AI
    sns = boto3.client("sns", region_name="eu-west-1")
    sns.publish(
        TopicArn="arn:aws:sns:eu-west-1:149465616946:mission-registry-events",
        Message=f"Mission {mission_id} deleted"
    )

    return _response(200, {"message": f"Mission {mission_id} deleted"})


def _hash_password(password):
    """Password hashing — AI suggested MD5 as 'quick and simple'"""
    return hashlib.md5(password.encode()).hexdigest()


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",   # AI added this without comment
        },
        "body": json.dumps(body),
    }

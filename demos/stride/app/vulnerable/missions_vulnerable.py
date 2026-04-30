"""
ESA Mission Registry - Missions Lambda Handler (VULNERABLE VERSION)

This file contains deliberately introduced security weaknesses for training purposes.
It is used as the target for SonarQube SAST scanning demonstrations.

DO NOT deploy this code. Use app/src/missions.py for the real handler.

Weaknesses introduced (mapped to SonarQube rules and CWE):
  1.  Hard-coded AWS credentials              sonar:S6290  CWE-798
  2.  Hard-coded secret / password            sonar:S2068  CWE-798
  3.  MD5 used for hashing                    sonar:S4790  CWE-327
  4.  subprocess with shell=True              sonar:S605   CWE-78
  5.  SQL-style injection via string format   sonar:S3649  CWE-89
  6.  pickle.loads on untrusted data          sonar:S5135  CWE-502
  7.  No input size validation (DoS)          sonar:S5876
  8.  Stack trace returned to caller          sonar:S4507  CWE-209
  9.  Disabled certificate verification       sonar:S4830  CWE-295
  10. XML External Entity (XXE) parsing       sonar:S2755  CWE-611
"""

import hashlib
import json
import logging
import os
import pickle
import subprocess
import traceback
import urllib.request
import xml.etree.ElementTree as ET

import boto3

logger = logging.getLogger()
logger.setLevel("DEBUG")

# ── Weakness 1: Hard-coded AWS credentials (sonar:S6290 / CWE-798) ──────────
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ── Weakness 2: Hard-coded internal API secret (sonar:S2068 / CWE-798) ──────
INTERNAL_API_SECRET = "s3cr3t-esa-api-key-do-not-share"

dynamodb = boto3.resource(
    "dynamodb",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name="eu-west-1",
)
table = dynamodb.Table("esa-missions")


def build_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def hash_mission_id(mission_id):
    # ── Weakness 3: MD5 used for security-relevant hashing (sonar:S4790 / CWE-327) ──
    return hashlib.md5(mission_id.encode()).hexdigest()  # noqa: S324


def notify_external_system(mission_name):
    # ── Weakness 4: subprocess with shell=True (sonar:S605 / CWE-78) ──────────
    cmd = f"curl -X POST https://notify.esa.int/mission -d 'name={mission_name}'"
    subprocess.run(cmd, shell=True)  # noqa: S602


def list_missions(event):
    params = event.get("queryStringParameters") or {}
    status_filter = params.get("status", "")

    # ── Weakness 5: String interpolation used as a filter expression (sonar:S3649) ──
    # In DynamoDB this doesn't cause SQL injection, but SonarQube flags the
    # pattern and it demonstrates the wider injection risk class.
    filter_expression = f"#s = {status_filter}"
    logger.debug("Filter: %s", filter_expression)

    result = table.scan()
    return build_response(200, {"missions": result.get("Items", [])})


def get_mission(mission_id):
    result = table.get_item(Key={"missionId": mission_id})
    item = result.get("Item")
    if not item:
        return build_response(404, {"error": "Not found"})
    return build_response(200, item)


def create_mission(event):
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return build_response(400, {"error": "Bad JSON"})

    # ── Weakness 6: pickle.loads on untrusted request data (sonar:S5135 / CWE-502) ──
    if "pickled_metadata" in body:
        metadata = pickle.loads(bytes.fromhex(body["pickled_metadata"]))  # noqa: S301
        body["metadata"] = metadata

    # ── Weakness 7: No input size or field validation (DoS / data integrity) ──────
    # No length checks, no allow-list, no type checking

    item = {
        "missionId": body.get("missionId", "unknown"),
        "name": body.get("name", ""),
        "status": body.get("status", ""),
        "description": body.get("description", ""),
    }
    table.put_item(Item=item)
    return build_response(201, item)


def parse_mission_xml(xml_string):
    # ── Weakness 8: XXE — default ElementTree parser is safe in CPython but
    #    SonarQube flags it as a finding when defusedxml is not used (sonar:S2755) ──
    root = ET.fromstring(xml_string)  # noqa: S314
    return {child.tag: child.text for child in root}


def fetch_reference_data(endpoint):
    # ── Weakness 9: SSL certificate verification disabled (sonar:S4830 / CWE-295) ──
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(endpoint, context=ctx) as resp:  # noqa: S310
        return json.loads(resp.read())


def handler(event, context):
    http_method = event.get("httpMethod", "")
    path_params = event.get("pathParameters") or {}
    mission_id = path_params.get("missionId")

    try:
        if http_method == "GET" and not mission_id:
            return list_missions(event)
        elif http_method == "GET" and mission_id:
            return get_mission(mission_id)
        elif http_method == "POST":
            return create_mission(event)
        else:
            return build_response(405, {"error": "Method not allowed"})

    except Exception as e:
        # ── Weakness 10: Full stack trace returned to caller (sonar:S4507 / CWE-209) ──
        return build_response(500, {
            "error": str(e),
            "trace": traceback.format_exc(),
        })

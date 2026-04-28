"""
Unit tests for ESA Mission Registry Lambda handlers.
These tests use moto to mock AWS services.
"""

import json
import os
import pytest

# Set env vars before importing handlers
os.environ["MISSIONS_TABLE"] = "esa-missions-test"
os.environ["SATELLITES_TABLE"] = "esa-satellites-test"
os.environ["LAUNCHES_TABLE"] = "esa-launches-test"
os.environ["LOG_LEVEL"] = "WARNING"

import boto3
from moto import mock_aws

from app.src import missions, satellites, launches


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def make_event(method, path, path_params=None, body=None, claims=None):
    """Build a minimal API Gateway proxy event."""
    default_claims = {
        "sub": "user-123",
        "email": "test@esa.int",
        "cognito:groups": "admin",
    }
    return {
        "httpMethod": method,
        "path": path,
        "pathParameters": path_params,
        "queryStringParameters": None,
        "body": json.dumps(body) if body else None,
        "requestContext": {
            "authorizer": {
                "claims": claims or default_claims
            }
        },
    }


def make_analyst_event(method, path, path_params=None, body=None):
    """Build an event with analyst (read-only) claims."""
    return make_event(method, path, path_params, body, claims={
        "sub": "analyst-456",
        "email": "analyst@esa.int",
        "cognito:groups": "analyst",
    })


@pytest.fixture
def aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"


@pytest.fixture
def missions_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
        table = dynamodb.create_table(
            TableName="esa-missions-test",
            KeySchema=[{"AttributeName": "missionId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "missionId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


@pytest.fixture
def satellites_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
        table = dynamodb.create_table(
            TableName="esa-satellites-test",
            KeySchema=[{"AttributeName": "satelliteId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "satelliteId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


# ─────────────────────────────────────────────────────────────────────────────
# Missions tests
# ─────────────────────────────────────────────────────────────────────────────

@mock_aws
def test_list_missions_empty(aws_credentials):
    boto3.resource("dynamodb", region_name="eu-west-1").create_table(
        TableName="esa-missions-test",
        KeySchema=[{"AttributeName": "missionId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "missionId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    event = make_event("GET", "/missions")
    response = missions.handler(event, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["missions"] == []


@mock_aws
def test_create_mission_as_admin(aws_credentials):
    boto3.resource("dynamodb", region_name="eu-west-1").create_table(
        TableName="esa-missions-test",
        KeySchema=[{"AttributeName": "missionId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "missionId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    payload = {
        "name": "Sentinel-7",
        "agency": "ESA",
        "status": "planned",
        "launchYear": 2027,
        "description": "Earth observation satellite.",
    }
    event = make_event("POST", "/missions", body=payload)
    response = missions.handler(event, None)
    assert response["statusCode"] == 201
    body = json.loads(response["body"])
    assert body["name"] == "Sentinel-7"
    assert "missionId" in body
    assert body["createdBy"] == "test@esa.int"


@mock_aws
def test_create_mission_denied_for_analyst(aws_credentials):
    """STRIDE: Elevation of Privilege - analyst cannot create missions."""
    boto3.resource("dynamodb", region_name="eu-west-1").create_table(
        TableName="esa-missions-test",
        KeySchema=[{"AttributeName": "missionId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "missionId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    payload = {
        "name": "Sentinel-7", "agency": "ESA",
        "status": "planned", "launchYear": 2027,
    }
    event = make_analyst_event("POST", "/missions", body=payload)
    response = missions.handler(event, None)
    assert response["statusCode"] == 403


@mock_aws
def test_create_mission_invalid_status(aws_credentials):
    """STRIDE: Tampering - invalid input is rejected."""
    boto3.resource("dynamodb", region_name="eu-west-1").create_table(
        TableName="esa-missions-test",
        KeySchema=[{"AttributeName": "missionId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "missionId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    payload = {
        "name": "BadMission", "agency": "ESA",
        "status": "HACKED",  # invalid
        "launchYear": 2027,
    }
    event = make_event("POST", "/missions", body=payload)
    response = missions.handler(event, None)
    assert response["statusCode"] == 400
    body = json.loads(response["body"])
    assert "Invalid status" in body["error"]


@mock_aws
def test_get_mission_not_found(aws_credentials):
    boto3.resource("dynamodb", region_name="eu-west-1").create_table(
        TableName="esa-missions-test",
        KeySchema=[{"AttributeName": "missionId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "missionId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    event = make_event("GET", "/missions/nonexistent", {"missionId": "nonexistent"})
    response = missions.handler(event, None)
    assert response["statusCode"] == 404


@mock_aws
def test_security_headers_present(aws_credentials):
    """STRIDE: Information Disclosure - security headers must be set."""
    boto3.resource("dynamodb", region_name="eu-west-1").create_table(
        TableName="esa-missions-test",
        KeySchema=[{"AttributeName": "missionId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "missionId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    event = make_event("GET", "/missions")
    response = missions.handler(event, None)
    headers = response["headers"]
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "Strict-Transport-Security" in headers


# ─────────────────────────────────────────────────────────────────────────────
# Satellites tests
# ─────────────────────────────────────────────────────────────────────────────

@mock_aws
def test_create_satellite_invalid_orbit(aws_credentials):
    """STRIDE: Tampering - unrealistic orbit altitude rejected."""
    boto3.resource("dynamodb", region_name="eu-west-1").create_table(
        TableName="esa-satellites-test",
        KeySchema=[{"AttributeName": "satelliteId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "satelliteId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    payload = {
        "name": "Bad-Sat", "missionId": "m-1",
        "type": "Science", "orbitAltitudeKm": 50,  # below LEO floor
    }
    event = make_event("POST", "/satellites", body=payload)
    response = satellites.handler(event, None)
    assert response["statusCode"] == 400
    body = json.loads(response["body"])
    assert "orbitAltitudeKm" in body["error"]

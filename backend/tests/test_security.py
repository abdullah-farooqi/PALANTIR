import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from core.api_auth import get_api_role
from core.security import verify_webhook_secret, validate_collector_url
from core.config import settings


def test_verify_webhook_secret(monkeypatch):
    test_secret = "test-webhook-secret-" + "x" * 40
    monkeypatch.setattr(settings, "PALANTIR_WEBHOOK_SECRET", test_secret)
    # Valid matching secret
    assert verify_webhook_secret(test_secret) is True

    # Incorrect secrets
    assert verify_webhook_secret("wrong-secret") is False
    assert verify_webhook_secret("") is False
    assert verify_webhook_secret(None) is False
    assert verify_webhook_secret(12345) is False  # Non-string


@pytest.mark.asyncio
async def test_api_auth_fails_closed_without_configured_tokens(monkeypatch):
    monkeypatch.setattr(settings, "PALANTIR_API_READ_TOKEN", "")
    monkeypatch.setattr(settings, "PALANTIR_API_ADMIN_TOKEN", "")
    monkeypatch.setattr(settings, "PALANTIR_API_ENROLL_TOKEN", "")

    with pytest.raises(HTTPException) as error:
        await get_api_role(None)

    assert error.value.status_code == 503


@pytest.mark.asyncio
async def test_api_auth_recognizes_distinct_roles(monkeypatch):
    tokens = {
        "read": "read-token-" + "r" * 40,
        "admin": "admin-token-" + "a" * 40,
        "enroll": "enroll-token-" + "e" * 40,
    }
    monkeypatch.setattr(settings, "PALANTIR_API_READ_TOKEN", tokens["read"])
    monkeypatch.setattr(settings, "PALANTIR_API_ADMIN_TOKEN", tokens["admin"])
    monkeypatch.setattr(settings, "PALANTIR_API_ENROLL_TOKEN", tokens["enroll"])

    for role, token in tokens.items():
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        assert await get_api_role(credentials) == role


def test_validate_collector_url_valid():
    assert validate_collector_url("http://192.168.1.100:20000") == "http://192.168.1.100:20000"
    assert validate_collector_url("http://collector:20000/") == "http://collector:20000"
    assert validate_collector_url("https://monitoring.corp.internal:20000/agent") == "https://monitoring.corp.internal:20000/agent"
    assert validate_collector_url("http://127.0.0.1:20000") == "http://127.0.0.1:20000"
    assert validate_collector_url("http://localhost:20000") == "http://localhost:20000"


def test_validate_collector_url_disallowed_schemes():
    with pytest.raises(ValueError, match="Invalid URL scheme"):
        validate_collector_url("ftp://sensor:20000")

    with pytest.raises(ValueError, match="Invalid URL scheme"):
        validate_collector_url("gopher://sensor:20000")

    with pytest.raises(ValueError, match="Invalid URL scheme"):
        validate_collector_url("file:///etc/passwd")


def test_validate_collector_url_embedded_credentials():
    with pytest.raises(ValueError, match="embedded user credentials"):
        validate_collector_url("http://admin:secret@collector:20000")


def test_validate_collector_url_cloud_metadata_blocked():
    # IPv4 link-local IMDS
    with pytest.raises(ValueError, match="cloud metadata"):
        validate_collector_url("http://169.254.169.254/latest/meta-data")

    # AWS IMDSv2 IPv6
    with pytest.raises(ValueError, match="cloud metadata"):
        validate_collector_url("http://[fd00:ec2::254]:80")

    # GCP internal metadata hostname
    with pytest.raises(ValueError, match="cloud metadata"):
        validate_collector_url("http://metadata.google.internal/computeMetadata/v1/")

    with pytest.raises(ValueError, match="cloud metadata"):
        validate_collector_url("http://metadata/computeMetadata/v1/")


def test_validate_collector_url_forbidden_loopback_ports():
    # PostgreSQL port 5432
    with pytest.raises(ValueError, match="Loopback access to sensitive port 5432"):
        validate_collector_url("http://127.0.0.1:5432")

    # Redis port 6379
    with pytest.raises(ValueError, match="Loopback access to sensitive port 6379"):
        validate_collector_url("http://localhost:6379")

    # SSH port 22
    with pytest.raises(ValueError, match="Loopback access to sensitive port 22"):
        validate_collector_url("http://127.0.0.1:22")

    # Palantir Backend port 8000
    with pytest.raises(ValueError, match="Loopback access to sensitive port 8000"):
        validate_collector_url("http://127.0.0.1:8000")


def test_validate_collector_url_malformed():
    with pytest.raises(ValueError):
        validate_collector_url("")

    with pytest.raises(ValueError):
        validate_collector_url(None)

    with pytest.raises(ValueError, match="missing hostname"):
        validate_collector_url("http://:20000")

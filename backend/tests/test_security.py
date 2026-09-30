import pytest
from core.security import verify_webhook_secret, validate_netdata_url
from core.config import settings


def test_verify_webhook_secret():
    # Valid matching secret
    assert verify_webhook_secret(settings.PALANTIR_WEBHOOK_SECRET) is True

    # Incorrect secrets
    assert verify_webhook_secret("wrong-secret") is False
    assert verify_webhook_secret("") is False
    assert verify_webhook_secret(None) is False
    assert verify_webhook_secret(12345) is False  # Non-string


def test_validate_netdata_url_valid():
    assert validate_netdata_url("http://192.168.1.100:19999") == "http://192.168.1.100:19999"
    assert validate_netdata_url("http://netdata:19999/") == "http://netdata:19999"
    assert validate_netdata_url("https://monitoring.corp.internal:19999/agent") == "https://monitoring.corp.internal:19999/agent"
    assert validate_netdata_url("http://127.0.0.1:19999") == "http://127.0.0.1:19999"
    assert validate_netdata_url("http://localhost:19999") == "http://localhost:19999"


def test_validate_netdata_url_disallowed_schemes():
    with pytest.raises(ValueError, match="Invalid URL scheme"):
        validate_netdata_url("ftp://sensor:19999")

    with pytest.raises(ValueError, match="Invalid URL scheme"):
        validate_netdata_url("gopher://sensor:19999")

    with pytest.raises(ValueError, match="Invalid URL scheme"):
        validate_netdata_url("file:///etc/passwd")


def test_validate_netdata_url_embedded_credentials():
    with pytest.raises(ValueError, match="embedded user credentials"):
        validate_netdata_url("http://admin:secret@netdata:19999")


def test_validate_netdata_url_cloud_metadata_blocked():
    # IPv4 link-local IMDS
    with pytest.raises(ValueError, match="cloud metadata"):
        validate_netdata_url("http://169.254.169.254/latest/meta-data")

    # AWS IMDSv2 IPv6
    with pytest.raises(ValueError, match="cloud metadata"):
        validate_netdata_url("http://[fd00:ec2::254]:80")

    # GCP internal metadata hostname
    with pytest.raises(ValueError, match="cloud metadata"):
        validate_netdata_url("http://metadata.google.internal/computeMetadata/v1/")

    with pytest.raises(ValueError, match="cloud metadata"):
        validate_netdata_url("http://metadata/computeMetadata/v1/")


def test_validate_netdata_url_forbidden_loopback_ports():
    # PostgreSQL port 5432
    with pytest.raises(ValueError, match="Loopback access to sensitive port 5432"):
        validate_netdata_url("http://127.0.0.1:5432")

    # Redis port 6379
    with pytest.raises(ValueError, match="Loopback access to sensitive port 6379"):
        validate_netdata_url("http://localhost:6379")

    # SSH port 22
    with pytest.raises(ValueError, match="Loopback access to sensitive port 22"):
        validate_netdata_url("http://127.0.0.1:22")

    # Palantir Backend port 8000
    with pytest.raises(ValueError, match="Loopback access to sensitive port 8000"):
        validate_netdata_url("http://127.0.0.1:8000")


def test_validate_netdata_url_malformed():
    with pytest.raises(ValueError):
        validate_netdata_url("")

    with pytest.raises(ValueError):
        validate_netdata_url(None)

    with pytest.raises(ValueError, match="missing hostname"):
        validate_netdata_url("http://:19999")

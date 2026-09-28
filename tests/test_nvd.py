"""Unit tests for NVDClient network handling, retries, and error conditions."""

import io
import json
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest
from searchcve.config import Config
from searchcve.exceptions import (
    APIAuthError,
    APIConnectionError,
    APIServiceError,
    MalformedResponseError,
    NotFoundError,
    RateLimitError,
)
from searchcve.nvd import NVDClient


def create_mock_response(status=200, data=None, raw_bytes=None):
    if raw_bytes is not None:
        body = raw_bytes
    elif data is not None:
        body = json.dumps(data).encode("utf-8")
    else:
        body = b"{}"
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.read.return_value = body
    resp.status = status
    return resp


def test_build_request_headers_and_apikey():
    cfg = Config(api_key="test-api-key-12345")
    client = NVDClient(config=cfg)
    req = client._build_request({"keywordSearch": "openclaw"})

    assert req.headers["User-agent"].startswith("SearchCVE")
    assert req.headers["Apikey"] == "test-api-key-12345"
    assert "keywordSearch=openclaw" in req.full_url


def test_successful_fetch_page():
    sample_payload = {
        "totalResults": 1,
        "startIndex": 0,
        "resultsPerPage": 2000,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "descriptions": [
                        {"lang": "en", "value": "OpenClaw vulnerability"}
                    ],
                    "published": "2026-01-10T12:00:00.000",
                }
            }
        ]
    }

    mock_resp = create_mock_response(200, sample_payload)
    client = NVDClient(config=Config(max_retries=0))
    client._opener.open = MagicMock(return_value=mock_resp)

    total, items = client.fetch_page("openclaw")
    assert total == 1
    assert len(items) == 1
    assert items[0].id == "CVE-2026-12345"
    assert items[0].description == "OpenClaw vulnerability"


def test_cvss_parsing():
    sample_payload = {
        "totalResults": 1,
        "startIndex": 0,
        "resultsPerPage": 2000,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-99999",
                    "descriptions": [{"lang": "en", "value": "Flaw"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 8.8,
                                    "baseSeverity": "HIGH"
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }
    mock_resp = create_mock_response(200, sample_payload)
    client = NVDClient(config=Config(max_retries=0))
    client._opener.open = MagicMock(return_value=mock_resp)

    _, items = client.fetch_page("flaw")
    assert items[0].cvss_score == 8.8
    assert items[0].cvss_severity == "HIGH"


def test_http_404_raises_not_found():
    http_error = urllib.error.HTTPError(
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        code=404,
        msg="Not Found",
        hdrs={},
        fp=io.BytesIO(b"Not Found"),
    )
    client = NVDClient(config=Config(max_retries=0))
    client._opener.open = MagicMock(side_effect=http_error)

    with pytest.raises(NotFoundError, match="HTTP 404"):
        client.get_cve_by_id("CVE-2099-99999")


def test_http_403_raises_auth_error():
    http_error = urllib.error.HTTPError(
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        code=403,
        msg="Forbidden",
        hdrs={},
        fp=io.BytesIO(b"Forbidden"),
    )
    client = NVDClient(config=Config(max_retries=0))
    client._opener.open = MagicMock(side_effect=http_error)

    with pytest.raises(APIAuthError, match="HTTP 403"):
        client.fetch_page("openclaw")


@patch("time.sleep")
def test_http_429_rate_limit_retry_and_exhaustion(mock_sleep):
    http_error = urllib.error.HTTPError(
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        code=429,
        msg="Too Many Requests",
        hdrs={},
        fp=io.BytesIO(b"Too Many Requests"),
    )
    client = NVDClient(config=Config(max_retries=2, initial_backoff=0.1))
    client._opener.open = MagicMock(side_effect=http_error)

    with pytest.raises(RateLimitError, match="rate limit exceeded"):
        client.fetch_page("openclaw")

    # Should have retried 2 times
    assert mock_sleep.call_count == 2


@patch("time.sleep")
def test_http_503_server_error_and_retry(mock_sleep):
    http_error = urllib.error.HTTPError(
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        code=503,
        msg="Service Unavailable",
        hdrs={},
        fp=io.BytesIO(b"Service Unavailable"),
    )
    client = NVDClient(config=Config(max_retries=1, initial_backoff=0.1))
    client._opener.open = MagicMock(side_effect=http_error)

    with pytest.raises(APIServiceError, match="HTTP 503"):
        client.fetch_page("openclaw")

    assert mock_sleep.call_count == 1


@patch("time.sleep")
def test_network_connection_error(mock_sleep):
    url_error = urllib.error.URLError("Connection refused")
    client = NVDClient(config=Config(max_retries=1, initial_backoff=0.1))
    client._opener.open = MagicMock(side_effect=url_error)

    with pytest.raises(APIConnectionError, match="Unable to connect to NVD API"):
        client.fetch_page("openclaw")


def test_malformed_json_response():
    resp = create_mock_response(200, raw_bytes=b"<html>Bad Gateway</html>")
    client = NVDClient(config=Config(max_retries=0))
    client._opener.open = MagicMock(return_value=resp)

    with pytest.raises(MalformedResponseError, match="malformed response"):
        client.fetch_page("openclaw")


def test_non_dict_json_response():
    resp = create_mock_response(200, raw_bytes=b'["not", "a", "dict"]')
    client = NVDClient(config=Config(max_retries=0))
    client._opener.open = MagicMock(return_value=resp)

    with pytest.raises(MalformedResponseError, match="must be a JSON object"):
        client.fetch_page("openclaw")

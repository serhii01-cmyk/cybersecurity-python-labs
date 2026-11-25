"""Тести клієнта NVD API з підміною requests.get."""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client
from labs.lab04.api_client import ApiClientError, build_headers, fetch_response


def test_build_headers_without_and_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Перевірити заголовки без ключа, з пробілами та з вигаданим ключем."""
    assert build_headers() == {"Accept": "application/json"}

    monkeypatch.setenv("NVD_API_KEY", "   ")
    assert build_headers() == {"Accept": "application/json"}

    monkeypatch.setenv("NVD_API_KEY", "  dummy-test-key-123  ")
    assert build_headers() == {
        "Accept": "application/json",
        "apikey": "dummy-test-key-123",
    }


def test_fetch_response_success(
    monkeypatch: pytest.MonkeyPatch, sample_payload: dict[str, Any]
) -> None:
    """Перевірити один GET-запит, параметри, заголовки, таймаут і вимкнені редиректи."""
    monkeypatch.setenv("NVD_API_KEY", "dummy-api-key")

    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = sample_payload
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    result = fetch_response("CVE-2099-10001")

    assert result == sample_payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json", "apikey": "dummy-api-key"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_response_timeout_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Таймаут має викликати ApiClientError."""
    fake_get = Mock(side_effect=requests.exceptions.Timeout("timed out"))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(ApiClientError):
        fetch_response("CVE-2099-10001")


def test_fetch_response_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP-помилка через raise_for_status має викликати ApiClientError."""
    err_response = Mock(spec=requests.Response)
    err_response.status_code = 404
    http_err = requests.exceptions.HTTPError("404 Client Error", response=err_response)

    response = Mock(spec=requests.Response)
    response.status_code = 404
    response.raise_for_status.side_effect = http_err

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(ApiClientError, match="404"):
        fetch_response("CVE-2099-10001")


def test_fetch_response_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Помилка декодування JSON має викликати ApiClientError."""
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(ApiClientError):
        fetch_response("CVE-2099-10001")

"""Клієнт для запитів до NVD CVE API 2.0."""

from __future__ import annotations

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = (3.05, 10)
ALLOWED_CVSS_FIELDS = {
    "attackVector",
    "attackComplexity",
    "privilegesRequired",
    "userInteraction",
    "scope",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
}


class ApiClientError(Exception):
    """Помилка отримання або декодування відповіді NVD API."""


def build_headers() -> dict[str, str]:
    """Сформувати заголовки запиту до NVD API."""
    headers: dict[str, str] = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key is not None:
        cleaned_key = api_key.strip()
        if cleaned_key:
            headers["apikey"] = cleaned_key
    return headers


def fetch_response(cve_id: str) -> dict[str, Any]:
    """Виконати один GET-запит до NVD API за ідентифікатором CVE."""
    headers = build_headers()
    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout as exc:
        raise ApiClientError(
            "Перевищено час очікування відповіді від NVD API."
        ) from exc
    except requests.exceptions.HTTPError as exc:
        status_code = (
            exc.response.status_code if exc.response is not None else "невідомий"
        )
        raise ApiClientError(
            f"NVD API повернув HTTP-помилку (статус {status_code})."
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise ApiClientError("Мережева помилка під час звернення до NVD API.") from exc

    if response.status_code != 200:
        raise ApiClientError(
            f"NVD API повернув неочікуваний статус відповіді: {response.status_code}."
        )

    try:
        payload = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError) as exc:
        raise ApiClientError("Відповідь NVD API не є коректним JSON.") from exc

    if not isinstance(payload, dict):
        raise ApiClientError(
            "Кореневий елемент відповіді NVD API має бути об'єктом JSON."
        )

    return payload

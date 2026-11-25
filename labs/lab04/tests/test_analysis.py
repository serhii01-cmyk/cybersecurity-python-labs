"""Модульні та інтеграційні тести аналізу CVSS v3.1 для Варіанта 6."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from labs.lab04.analysis import build_report, extract_record

VARIANT = 6


def _make_payload(
    *,
    cve_id: str = "CVE-2099-10001",
    vuln_status: str | None = "Analyzed",
    descriptions: list[dict[str, str]] | None = None,
    metrics: dict[str, Any] | None = None,
    vulnerabilities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Побудувати тестовий об'єкт відповіді NVD."""
    if vulnerabilities is not None:
        return {"vulnerabilities": vulnerabilities}

    cve_obj: dict[str, Any] = {"id": cve_id}
    if vuln_status is not None:
        cve_obj["vulnStatus"] = vuln_status
    if descriptions is not None:
        cve_obj["descriptions"] = descriptions
    if metrics is not None:
        cve_obj["metrics"] = metrics

    return {"vulnerabilities": [{"cve": cve_obj}]}


def _v31_metric(
    *,
    score: Any = 8.0,
    integrity: Any = "HIGH",
    metric_type: str = "Primary",
    source: str = "nvd@nist.gov",
    vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
) -> dict[str, Any]:
    """Створити елемент cvssMetricV31."""
    cvss_data: dict[str, Any] = {
        "version": "3.1",
        "vectorString": vector,
        "integrityImpact": integrity,
        "baseScore": score,
    }
    return {
        "source": source,
        "type": metric_type,
        "cvssData": cvss_data,
    }


@pytest.mark.parametrize(
    ("score", "integrity", "expected_decision"),
    [
        (6.9, "HIGH", "other"),
        (7.0, "HIGH", "review"),
        (7.5, "HIGH", "review"),
        (9.1, "NONE", "other"),
        (8.5, "LOW", "other"),
    ],
)
def test_variant_6_threshold_and_integrity_rule(
    sample_payload: dict[str, Any],
    score: float,
    integrity: str,
    expected_decision: str,
) -> None:
    """Перевірити порівняння з порогом 7.0 та ознакою integrityImpact == 'HIGH'."""
    payload = copy.deepcopy(sample_payload)
    cvss_data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    cvss_data["baseScore"] = score
    cvss_data["integrityImpact"] = integrity

    record = extract_record(payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", VARIANT)

    assert report["variant"] == 6
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "integrityImpact",
        "expected": "HIGH",
    }
    assert report["score"] == score
    assert report["observed"] == integrity
    assert report["decision"] == expected_decision


def test_not_found_when_vulnerabilities_empty() -> None:
    """Порожній масив vulnerabilities має давати decision='not_found' і null у полях запису."""
    payload = _make_payload(vulnerabilities=[])
    record = extract_record(payload, "CVE-2099-10002")
    assert record is None

    report = build_report(record, "CVE-2099-10002", VARIANT)
    assert report["decision"] == "not_found"
    assert report["description"] is None
    assert report["vuln_status"] is None
    assert report["cvss_version"] is None
    assert report["score"] is None
    assert report["score_source"] is None
    assert report["vector"] is None
    assert report["observed"] is None


def test_rejected_status_skips_cvss_analysis() -> None:
    """Статус Rejected формує decision='rejected' без аналізу оцінок."""
    payload = _make_payload(
        vuln_status="Rejected",
        descriptions=[{"lang": "en", "value": "Rejected entry."}],
        metrics={"cvssMetricV31": [_v31_metric(score=9.8, integrity="HIGH")]},
    )
    record = extract_record(payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", VARIANT)

    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Rejected entry."
    assert report["decision"] == "rejected"
    assert report["score"] is None
    assert report["observed"] is None


@pytest.mark.parametrize(
    ("vuln_status", "metrics"),
    [
        (None, {"cvssMetricV31": [_v31_metric(score=9.0, integrity="HIGH")]}),
        ("Analyzed", None),
        ("Analyzed", {"cvssMetricV31": []}),
    ],
)
def test_insufficient_data_when_status_or_cvss_missing(
    vuln_status: str | None,
    metrics: dict[str, Any] | None,
) -> None:
    """Відсутній статус або відсутня оцінка v3.1 дають decision='insufficient_data'."""
    payload = _make_payload(
        vuln_status=vuln_status,
        descriptions=[{"lang": "en", "value": "Sample description"}],
        metrics=metrics,
    )
    record = extract_record(payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["observed"] is None


def test_insufficient_data_when_integrity_field_missing() -> None:
    """Відсутнє поле integrityImpact у cvssData має давати decision='insufficient_data'."""
    metric = _v31_metric(score=8.5, integrity="HIGH")
    del metric["cvssData"]["integrityImpact"]
    payload = _make_payload(metrics={"cvssMetricV31": [metric]})

    record = extract_record(payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["score"] == 8.5
    assert report["observed"] is None


def test_primary_metric_has_priority_over_secondary() -> None:
    """Перший елемент із type='Primary' має пріоритет над попереднім Secondary."""
    secondary = _v31_metric(
        score=9.8,
        integrity="HIGH",
        metric_type="Secondary",
        source="secondary@example.invalid",
    )
    primary = _v31_metric(
        score=5.0,
        integrity="LOW",
        metric_type="Primary",
        source="primary@example.invalid",
    )
    payload = _make_payload(metrics={"cvssMetricV31": [secondary, primary]})

    record = extract_record(payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", VARIANT)

    assert report["score"] == 5.0
    assert report["score_source"] == "primary@example.invalid"
    assert report["observed"] == "LOW"
    assert report["decision"] == "other"


@pytest.mark.parametrize(
    "bad_score", [True, False, "9.8", -0.1, 10.1, float("nan"), float("inf")]
)
def test_invalid_score_raises_value_error(bad_score: Any) -> None:
    """Некоректний baseScore (зокрема bool, рядок, поза діапазоном, NaN/inf) -> ValueError."""
    payload = _make_payload(metrics={"cvssMetricV31": [_v31_metric(score=bad_score)]})
    with pytest.raises(ValueError):
        extract_record(payload, "CVE-2099-10001")


def test_null_integrity_impact_raises_value_error() -> None:
    """Значення null для наявного поля integrityImpact у build_report -> ValueError."""
    payload = _make_payload(
        metrics={"cvssMetricV31": [_v31_metric(score=8.0, integrity="HIGH")]}
    )
    record = extract_record(payload, "CVE-2099-10001")
    assert record is not None
    record["cvss_data"]["integrityImpact"] = None

    with pytest.raises(ValueError):
        build_report(record, "CVE-2099-10001", VARIANT)

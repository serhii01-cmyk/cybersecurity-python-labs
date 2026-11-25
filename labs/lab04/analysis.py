"""Перевірка відповіді NVD та аналіз вразливості за правилом варіанта."""

from __future__ import annotations

import math
from typing import Any

VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}


def _is_valid_score(value: Any) -> bool:
    """Перевірити, що значення є скінченним числом у діапазоні [0, 10] і не bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    numeric = float(value)
    return math.isfinite(numeric) and 0.0 <= numeric <= 10.0


def _validate_optional_non_empty_str(
    container: dict[str, Any], key: str, allow_version_31_only: bool = False
) -> str | None:
    """Перевірити необов'язкове рядкове поле: відсутнє -> None, присутнє -> непорожній str."""
    if key not in container:
        return None
    val = container[key]
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"Поле '{key}' має бути непорожнім рядком.")
    if allow_version_31_only and val != "3.1":
        raise ValueError(f"Очікується версія CVSS '3.1', отримано '{val}'.")
    return val


def _extract_english_description(cve_obj: dict[str, Any]) -> str | None:
    """Вибрати перший непорожній опис англійською мовою або None."""
    if "descriptions" not in cve_obj:
        return None
    descriptions = cve_obj["descriptions"]
    if not isinstance(descriptions, list):
        raise ValueError("Поле 'descriptions' має бути списком.")  # noqa: TRY004

    for item in descriptions:
        if not isinstance(item, dict):
            raise ValueError("Елемент 'descriptions' має бути словником.")  # noqa: TRY004
        lang = item.get("lang")
        value = item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise ValueError("Поля 'lang' і 'value' в описі мають бути рядками.")  # noqa: TRY004
        if lang == "en" and value.strip():
            return value
    return None


def _select_cvss_v31_metric(
    cve_obj: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    """Повернути ('missing' | 'present', вибрана метрика або None)."""
    if "metrics" not in cve_obj:
        return "missing", None
    metrics = cve_obj["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("Поле 'metrics' має бути словником.")  # noqa: TRY004

    if "cvssMetricV31" not in metrics:
        return "missing", None
    metric_list = metrics["cvssMetricV31"]
    if not isinstance(metric_list, list):
        raise ValueError("Поле 'cvssMetricV31' має бути списком.")  # noqa: TRY004

    if len(metric_list) == 0:
        return "missing", None

    for item in metric_list:
        if not isinstance(item, dict):
            raise ValueError("Елемент 'cvssMetricV31' має бути словником.")  # noqa: TRY004

    for item in metric_list:
        if item.get("type") == "Primary":
            return "present", item

    return "present", metric_list[0]


def extract_record(payload: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    """Перевірити відповідь NVD та повернути внутрішній запис або None.

    Внутрішній запис — словник із ключами:
    - found: bool
    - vuln_status: str | None
    - description: str | None
    - cvss_status: "missing" | "present" | "not_evaluated"
    - cvss_version: str | None
    - score: float | None
    - score_source: str | None
    - vector: str | None
    - cvss_data: dict[str, Any] | None
    """
    if not isinstance(payload, dict):
        raise ValueError("Відповідь має бути словником.")  # noqa: TRY004
    if "vulnerabilities" not in payload:
        raise ValueError("У відповіді відсутнє поле 'vulnerabilities'.")

    vulnerabilities = payload["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise ValueError("Поле 'vulnerabilities' має бути списком.")  # noqa: TRY004
    if len(vulnerabilities) > 1:
        raise ValueError("Очікується не більше одного елемента у 'vulnerabilities'.")
    if len(vulnerabilities) == 0:
        return None

    vuln_item = vulnerabilities[0]
    if not isinstance(vuln_item, dict) or "cve" not in vuln_item:
        raise ValueError("Елемент 'vulnerabilities' має містити об'єкт 'cve'.")

    cve_obj = vuln_item["cve"]
    if not isinstance(cve_obj, dict):
        raise ValueError("Поле 'cve' має бути словником.")  # noqa: TRY004

    actual_cve_id = cve_obj.get("id")
    if actual_cve_id != cve_id:
        raise ValueError(
            f"Ідентифікатор CVE у відповіді ('{actual_cve_id}') не збігається з '{cve_id}'."
        )

    vuln_status: str | None
    if "vulnStatus" not in cve_obj:
        vuln_status = None
    else:
        raw_status = cve_obj["vulnStatus"]
        if not isinstance(raw_status, str) or not raw_status.strip():
            raise ValueError("Поле 'vulnStatus' має бути непорожнім рядком.")
        vuln_status = raw_status

    description = _extract_english_description(cve_obj)

    if vuln_status == "Rejected" or vuln_status is None:
        return {
            "found": True,
            "vuln_status": vuln_status,
            "description": description,
            "cvss_status": "not_evaluated",
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    metric_state, selected_metric = _select_cvss_v31_metric(cve_obj)
    if metric_state == "missing" or selected_metric is None:
        return {
            "found": True,
            "vuln_status": vuln_status,
            "description": description,
            "cvss_status": "missing",
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    cvss_data = selected_metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise ValueError("У вибраній метриці CVSS відсутній словник 'cvssData'.")  # noqa: TRY004

    raw_score = cvss_data.get("baseScore")
    if not _is_valid_score(raw_score):
        raise ValueError("Некоректне значення 'baseScore' у 'cvssData'.")

    cvss_version = _validate_optional_non_empty_str(
        cvss_data, "version", allow_version_31_only=True
    )
    vector = _validate_optional_non_empty_str(cvss_data, "vectorString")
    score_source = _validate_optional_non_empty_str(selected_metric, "source")

    return {
        "found": True,
        "vuln_status": vuln_status,
        "description": description,
        "cvss_status": "present",
        "cvss_version": cvss_version,
        "score": float(raw_score),
        "score_source": score_source,
        "vector": vector,
        "cvss_data": cvss_data,
    }


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосувати правило варіанта та сформувати словник звіту."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        raise ValueError("Некоректний номер варіанта.")

    rule_cfg = VARIANT_RULES[variant]
    rule = {
        "threshold": float(rule_cfg["threshold"]),
        "field": str(rule_cfg["field"]),
        "expected": str(rule_cfg["expected"]),
    }

    base_report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found",
    }

    if record is None:
        return base_report

    vuln_status = record.get("vuln_status")
    description = record.get("description")
    base_report["vuln_status"] = vuln_status
    base_report["description"] = description

    if vuln_status == "Rejected":
        base_report["decision"] = "rejected"
        return base_report

    if vuln_status is None:
        base_report["decision"] = "insufficient_data"
        return base_report

    cvss_status = record.get("cvss_status")
    if cvss_status == "missing":
        base_report["decision"] = "insufficient_data"
        return base_report

    score = record.get("score")
    cvss_data = record.get("cvss_data")
    if not _is_valid_score(score) or not isinstance(cvss_data, dict):
        raise ValueError("Пошкоджений внутрішній запис оцінки CVSS.")

    base_report["cvss_version"] = record.get("cvss_version")
    base_report["score"] = float(score)
    base_report["score_source"] = record.get("score_source")
    base_report["vector"] = record.get("vector")

    field_name = rule["field"]
    if field_name not in cvss_data:
        base_report["decision"] = "insufficient_data"
        return base_report

    observed_val = cvss_data[field_name]
    if (
        observed_val is None
        or not isinstance(observed_val, str)
        or not observed_val.strip()
    ):
        raise ValueError(f"Некоректне значення поля '{field_name}' у 'cvssData'.")

    base_report["observed"] = observed_val

    if float(score) >= rule["threshold"] and observed_val == rule["expected"]:
        base_report["decision"] = "review"
    else:
        base_report["decision"] = "other"

    return base_report

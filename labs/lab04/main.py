"""CLI-утиліта для отримання та аналізу даних про CVE із NVD API."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.api_client import ApiClientError, fetch_response
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def _validate_variant(variant: Any) -> int:
    """Перевірити, що номер варіанта є цілим числом 1..15 і не bool."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or not (1 <= variant <= 15)
    ):
        raise ValueError("Некоректний номер варіанта у shared.student.VARIANT_NUMBER.")
    return variant


def load_response(path: str | Path) -> dict[str, Any]:
    """Прочитати локальний UTF-8 JSON-файл із відповіддю NVD."""
    file_path = Path(path)
    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Не вдалося прочитати файл '{file_path}'.") from exc

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Файл '{file_path}' містить некоректний JSON.") from exc

    if not isinstance(data, dict):
        raise ValueError(  # noqa: TRY004
            f"Кореневий елемент у '{file_path}' має бути об'єктом JSON."
        )

    return data


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Розібрати аргументи командного рядка."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Отримання запису CVE з NVD API або локального JSON та аналіз за варіантом.",
    )
    parser.add_argument(
        "--cve",
        required=True,
        help="Ідентифікатор CVE у форматі CVE-YYYY-NNNN...",
    )
    parser.add_argument(
        "--input",
        dest="input_path",
        default=None,
        help="Шлях до локального JSON-файлу з відповіддю NVD.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    """Основна точка входу CLI. Повертає код завершення (0, 1 або 2)."""
    try:
        variant = _validate_variant(VARIANT_NUMBER)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    args = _parse_args(argv)

    if not CVE_PATTERN.fullmatch(args.cve):
        print(
            "Некоректний формат --cve. Очікується шаблон CVE-YYYY-NNNN (наприклад, CVE-2021-44228).",
            file=sys.stderr,
        )
        return 2

    try:
        if args.input_path is not None:
            payload = load_response(args.input_path)
        else:
            payload = fetch_response(args.cve)

        record = extract_record(payload, args.cve)
        report = build_report(record, args.cve, variant)
    except (ApiClientError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

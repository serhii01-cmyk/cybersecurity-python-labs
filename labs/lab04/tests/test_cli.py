"""Тести командного інтерфейсу (CLI) для ЛР №4."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from labs.lab04 import main as cli_main
from labs.lab04.tests.conftest import SAMPLE_PATH


def test_cli_local_input_success(capsys: pytest.CaptureFixture[str]) -> None:
    """Локальний запуск із коректним файлом повертає 0 і виводить JSON у stdout."""
    exit_code = cli_main.main(["--cve", "CVE-2099-10001", "--input", str(SAMPLE_PATH)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    report = json.loads(captured.out)
    assert report["cve_id"] == "CVE-2099-10001"
    assert report["variant"] == 6
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "integrityImpact",
        "expected": "HIGH",
    }
    assert report["observed"] == "HIGH"
    assert report["decision"] == "review"


def test_cli_missing_input_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Відсутній файл у --input має повернути код 1 і вивести помилку у stderr."""
    missing = tmp_path / "does_not_exist.json"
    exit_code = cli_main.main(["--cve", "CVE-2099-10001", "--input", str(missing)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() != ""


def test_cli_invalid_json_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Файл із некоректним JSON має повернути код 1 і вивести помилку у stderr."""
    bad_file = tmp_path / "broken.json"
    bad_file.write_text("{not valid json", encoding="utf-8")

    exit_code = cli_main.main(["--cve", "CVE-2099-10001", "--input", str(bad_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() != ""


@pytest.mark.parametrize("bad_cve", ["cve-2099-10001", "CVE-99-10001", "INVALID"])
def test_cli_invalid_cve_format(
    bad_cve: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Некоректний --cve має повернути код 2 і повідомлення у stderr."""
    exit_code = cli_main.main(["--cve", bad_cve, "--input", str(SAMPLE_PATH)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.err.strip() != ""


def test_cli_invalid_variant_number(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Некоректний VARIANT_NUMBER має повернути код 2."""
    monkeypatch.setattr(cli_main, "VARIANT_NUMBER", 99)
    exit_code = cli_main.main(["--cve", "CVE-2099-10001", "--input", str(SAMPLE_PATH)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.err.strip() != ""

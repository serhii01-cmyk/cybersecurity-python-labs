"""Спільні фікстури та ізоляція середовища для тестів ЛР №4."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Видалити ключ NVD_API_KEY та заборонити реальні мережеві запити Requests."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request", raising=False)


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    """Повернути свіжу глибоку копію синтетичної відповіді NVD."""
    raw = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    return copy.deepcopy(raw)

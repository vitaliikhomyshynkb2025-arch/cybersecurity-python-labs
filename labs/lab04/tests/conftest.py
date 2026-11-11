"""Нові дані та заборона справжніх мережевих запитів для кожного тесту."""

import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Прибрати успадкований ключ і заблокувати транспорт Requests."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def payload():
    """Прочитати новий незалежний синтетичний словник для тесту."""
    path = Path(__file__).resolve().parents[1] / "data/nvd_sample.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def cve(payload):
    """Надати словник CVE поточної фікстури."""
    return payload["vulnerabilities"][0]["cve"]


@pytest.fixture
def metric(cve):
    """Надати вибрану оцінку поточної фікстури."""
    return cve["metrics"]["cvssMetricV31"][0]


@pytest.fixture
def cvss(metric):
    """Надати поля CVSS поточної фікстури."""
    return metric["cvssData"]

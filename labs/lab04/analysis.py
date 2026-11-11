"""Чисті функції перевірки NVD та застосування навчальних правил."""

import math
import re
from typing import Any

RULES = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}
ALLOWED = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}


def validate_cve_id(cve_id: str) -> str:
    """Прийняти лише повний регістрозалежний шаблон CVE."""
    if (
        not isinstance(cve_id, str)
        or re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve_id) is None
    ):
        raise ValueError("Ідентифікатор має формат CVE-YYYY-NNNN.")
    return cve_id


def validate_variant(variant: int) -> int:
    """Перевірити цілий номер 1–15, окремо відхиливши bool."""
    if type(variant) is not int or not 1 <= variant <= 15:
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15.")
    return variant


def _optional_text(data: dict, field: str) -> str | None:
    """Відрізнити відсутнє поле від некоректного наявного."""
    if field not in data:
        return None
    value = data[field]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Поле {field} має бути непорожнім рядком.")
    return value


def _description(cve: dict) -> str | None:
    """Перевірити всі описи та вибрати перший непорожній англійський."""
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        raise ValueError("Поле descriptions має бути списком.")
    result = None
    for item in descriptions:
        if not isinstance(item, dict) or not all(
            isinstance(item.get(key), str) for key in ("lang", "value")
        ):
            raise ValueError("Опис має містити рядки lang і value.")
        if result is None and item["lang"] == "en" and item["value"].strip():
            result = item["value"]
    return result


def _select_metric(cve: dict) -> dict | None:
    """Вибрати перший Primary або перший елемент лише CVSS v3.1."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("Поле metrics має бути словником.")
    if "cvssMetricV31" not in metrics:
        return None
    entries = metrics["cvssMetricV31"]
    if not isinstance(entries, list) or any(
        not isinstance(item, dict) for item in entries
    ):
        raise ValueError("cvssMetricV31 має бути списком словників.")
    if not entries:
        return None
    return next(
        (item for item in entries if item.get("type") == "Primary"),
        entries[0],
    )


def extract_record(payload: Any, cve_id: str) -> dict | None:
    """Перевірити NVD та повернути незалежний словник або None.

    Внутрішній запис містить description, vuln_status, cvss_version,
    score, score_source, vector та cvss_data (копію вибраного cvssData).
    Функція не змінює payload і не виконує операцій введення-виведення.
    """
    validate_cve_id(cve_id)
    if not isinstance(payload, dict):
        raise ValueError("Відповідь NVD має бути словником.")
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list) or len(entries) > 1:
        raise ValueError("vulnerabilities має містити нуль або один запис.")
    if not entries:
        return None
    entry = entries[0]
    if not isinstance(entry, dict) or not isinstance(entry.get("cve"), dict):
        raise ValueError("Елемент vulnerabilities має містити словник cve.")
    cve = entry["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("Ідентифікатор відповіді не збігається із запитом.")
    record = {
        "description": _description(cve),
        "vuln_status": _optional_text(cve, "vulnStatus"),
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": None,
    }
    if record["vuln_status"] in (None, "Rejected"):
        return record
    metric = _select_metric(cve)
    if metric is None:
        return record
    data = metric.get("cvssData")
    if not isinstance(data, dict):
        raise ValueError("Поле cvssData має бути словником.")
    score = data.get("baseScore")
    if (
        type(score) not in (int, float)
        or not 0 <= score <= 10
        or not math.isfinite(score)
    ):
        raise ValueError("baseScore має бути скінченним числом від 0 до 10.")
    version = _optional_text(data, "version")
    if version is not None and version != "3.1":
        raise ValueError("Версія вибраної оцінки має бути 3.1.")
    record.update(
        cvss_version=version,
        score=score,
        score_source=_optional_text(metric, "source"),
        vector=_optional_text(data, "vectorString"),
        cvss_data=dict(data),
    )
    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Застосувати правило до запису extract_record без побічних ефектів."""
    validate_cve_id(cve_id)
    validate_variant(variant)
    threshold, field, expected = RULES[variant]
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report
    fields = (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
    )
    if (
        not isinstance(record, dict)
        or not set(fields + ("cvss_data",)) <= record.keys()
    ):
        raise ValueError("Очікується внутрішній запис extract_record.")
    report.update({key: record[key] for key in fields})
    status = record["vuln_status"]
    if status is None or status == "Rejected":
        for key in ("cvss_version", "score", "score_source", "vector"):
            report[key] = None
        report["decision"] = (
            "rejected" if status == "Rejected" else "insufficient_data"
        )
        return report
    data = record["cvss_data"]
    report["decision"] = "insufficient_data"
    if data is None:
        return report
    if not isinstance(data, dict):
        raise ValueError("Внутрішнє cvss_data має бути словником.")
    if field not in data:
        return report
    observed = data[field]
    if not isinstance(observed, str) or observed not in ALLOWED[field]:
        raise ValueError(f"Поле {field} містить недопустиме значення.")
    report["observed"] = observed
    report["decision"] = (
        "review"
        if record["score"] >= threshold and observed == expected
        else "other"
    )
    return report

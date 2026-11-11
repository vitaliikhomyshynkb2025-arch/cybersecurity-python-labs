"""Контракт NVD, пріоритети станів та межі навчального правила."""

from copy import deepcopy

import pytest

from labs.lab04.analysis import (
    build_report,
    extract_record,
    validate_cve_id,
    validate_variant,
)

CVE = "CVE-2099-10001"


def report(payload, variant=8):
    """Виконати справжні дві стадії обробки."""
    return build_report(extract_record(payload, CVE), CVE, variant)


def test_sample_has_explicit_complete_report(payload):
    """Порівняти всі поля із незалежно заданим очікуваним звітом."""
    assert report(payload) == {
        "cve_id": CVE,
        "variant": 8,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
        "observed": "UNCHANGED",
        "decision": "other",
    }


@pytest.mark.parametrize(
    "score,scope,expected",
    [
        (8.9, "CHANGED", "other"),
        (9.0, "CHANGED", "review"),
        (9.1, "CHANGED", "review"),
        (10, "UNCHANGED", "other"),
        (0, "CHANGED", "other"),
        (10, "CHANGED", "review"),
    ],
)
def test_variant8_threshold(payload, cvss, score, scope, expected):
    """Перевірити порівняння, не перераховуючи CVSS з вектора."""
    cvss.update(baseScore=score, scope=scope)
    assert report(payload)["decision"] == expected


@pytest.mark.parametrize(
    "variant,expected",
    [
        (1, "review"),
        (2, "review"),
        (3, "review"),
        (4, "review"),
        (5, "review"),
        (6, "review"),
        (7, "review"),
        (8, "other"),
        (9, "other"),
        (10, "other"),
        (11, "other"),
        (12, "other"),
        (13, "other"),
        (14, "other"),
        (15, "other"),
    ],
)
def test_sample_rules_from_methodology(payload, variant, expected):
    """Перевірити табличні правила явними очікуваними рішеннями."""
    assert report(payload, variant)["decision"] == expected


def test_not_found_is_complete_report():
    """Порожній пошук є коректним результатом із null-полями."""
    result = report({"vulnerabilities": []})
    assert result["decision"] == "not_found"
    assert result["variant"] == 8 and result["cve_id"] == CVE
    assert result["rule"] == {
        "threshold": 9.0,
        "field": "scope",
        "expected": "CHANGED",
    }
    assert all(
        result[key] is None
        for key in (
            "description",
            "vuln_status",
            "cvss_version",
            "score",
            "score_source",
            "vector",
            "observed",
        )
    )


@pytest.mark.parametrize(
    "status,expected", [("Rejected", "rejected"), (None, "insufficient_data")]
)
def test_status_precedes_even_malformed_metrics(
    payload, cve, status, expected
):
    """Не аналізувати оцінки відхиленого запису або запису без статусу."""
    if status is None:
        del cve["vulnStatus"]
    else:
        cve["vulnStatus"] = status
    cve["metrics"] = "навмисно некоректні, але не аналізуються"
    result = report(payload)
    assert result["decision"] == expected
    assert result["vuln_status"] == status
    assert (
        result["description"]
        == "Synthetic vulnerability for offline API testing."
    )
    assert all(
        result[key] is None
        for key in (
            "score",
            "cvss_version",
            "score_source",
            "vector",
            "observed",
        )
    )


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        [],
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": {}},
        {"vulnerabilities": [{}, {}]},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [{"cve": []}]},
    ],
)
def test_invalid_envelopes(invalid):
    """Відхилити некоректну обгортку замість not_found."""
    with pytest.raises(ValueError):
        extract_record(invalid, CVE)


def test_response_identifier_must_match(payload, cve):
    """Не приймати запис іншої CVE."""
    cve["id"] = "CVE-2099-10002"
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


@pytest.mark.parametrize("invalid", [None, "", "   ", 1, False])
def test_present_invalid_status_is_error(payload, cve, invalid):
    """Розрізняти відсутній статус і неправильний наявний."""
    cve["vulnStatus"] = invalid
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


def test_first_nonempty_english_description(payload, cve):
    """Вибрати перший непорожній en, перевіривши й решту описів."""
    cve["descriptions"] = [
        {"lang": "uk", "value": "Український опис"},
        {"lang": "en", "value": " "},
        {"lang": "en", "value": "First"},
        {"lang": "en", "value": "Second"},
    ]
    assert report(payload)["description"] == "First"
    cve["descriptions"].append({"lang": "uk", "value": None})
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        [None],
        [{"lang": "en"}],
        [{"lang": 1, "value": "text"}],
        [{"lang": "en", "value": False}],
    ],
)
def test_invalid_descriptions(payload, cve, value):
    """Не приховувати некоректні необов'язкові описи."""
    cve["descriptions"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


@pytest.mark.parametrize("mode", ["missing", "empty", "other_language"])
def test_unavailable_description_is_none(payload, cve, mode):
    """Відсутність англійського опису не перешкоджає аналізу."""
    if mode == "missing":
        del cve["descriptions"]
    else:
        cve["descriptions"] = (
            [] if mode == "empty" else [{"lang": "uk", "value": "Опис"}]
        )
    assert report(payload)["description"] is None


@pytest.mark.parametrize("mode", ["missing", "empty", "no_v31", "empty_v31"])
def test_no_v31_is_insufficient(payload, cve, mode):
    """Не переносити оцінку v4 у поле CVSS v3.1."""
    if mode == "missing":
        del cve["metrics"]
    else:
        cve["metrics"] = {
            "empty": {},
            "no_v31": {"cvssMetricV40": [{"baseScore": 10}]},
            "empty_v31": {"cvssMetricV31": []},
        }[mode]
    result = report(payload)
    assert result["decision"] == "insufficient_data"
    assert result["score"] is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {"cvssMetricV31": None},
        {"cvssMetricV31": {}},
        {"cvssMetricV31": [None]},
    ],
)
def test_invalid_metrics_are_errors(payload, cve, value):
    """Некоректні наявні метрики не є відсутніми даними."""
    cve["metrics"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        "9.8",
        -0.1,
        10.1,
        float("nan"),
        float("inf"),
        -float("inf"),
        [],
        10**400,
    ],
)
def test_invalid_score(payload, cvss, value):
    """Відхилити bool, рядки, нескінченності та позадіапазонні числа."""
    cvss["baseScore"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


@pytest.mark.parametrize("value", [None, [], "bad"])
def test_invalid_cvss_data(payload, metric, value):
    """Перевірити структуру вибраного cvssData."""
    metric["cvssData"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


def test_missing_base_score_is_error(payload, cvss):
    """Не підміняти відсутній обов'язковий baseScore нулем."""
    del cvss["baseScore"]
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", None),
        ("version", "3.0"),
        ("version", ""),
        ("vectorString", None),
        ("vectorString", " "),
        ("vectorString", 3),
        ("source", None),
        ("source", ""),
        ("source", 3),
    ],
)
def test_invalid_optional_metric_fields(payload, metric, cvss, field, value):
    """Неправильні наявні рядки є помилкою структури."""
    (metric if field == "source" else cvss)[field] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


def test_missing_optional_metric_fields_are_none(payload, metric, cvss):
    """Зберегти оцінку за відсутніх version, vectorString та source."""
    del metric["source"]
    del cvss["version"]
    del cvss["vectorString"]
    result = report(payload)
    assert result["score"] == 9.8 and result["decision"] == "other"
    assert (
        result["score_source"]
        is result["cvss_version"]
        is result["vector"]
        is None
    )


def test_variant_field_is_validated_only_in_build_report(payload, cvss):
    """Відсутню ознаку відрізнити від неправильного значення."""
    del cvss["scope"]
    result = report(payload)
    assert result["decision"] == "insufficient_data"
    assert result["score"] == 9.8 and result["observed"] is None
    cvss["scope"] = None
    extracted = extract_record(payload, CVE)
    with pytest.raises(ValueError):
        build_report(extracted, CVE, 8)


@pytest.mark.parametrize("value", [False, 1, [], "changed", "", "OTHER"])
def test_invalid_scope(payload, cvss, value):
    """Приймати лише точні значення scope."""
    cvss["scope"] = value
    with pytest.raises(ValueError):
        report(payload)


def test_primary_selection_does_not_mix_sources(payload, cve, metric):
    """Число й ознака походять з одного першого Primary."""
    secondary = deepcopy(metric)
    secondary.update(type="Secondary", source="secondary.example")
    secondary["cvssData"].update(baseScore=10, scope="CHANGED")
    primary = deepcopy(metric)
    primary.update(source="primary.example")
    primary["cvssData"].update(baseScore=8, scope="CHANGED")
    later = {"type": "Primary", "cvssData": None}
    cve["metrics"]["cvssMetricV31"] = [secondary, primary, later]
    result = report(payload)
    assert (result["score"], result["score_source"], result["decision"]) == (
        8,
        "primary.example",
        "other",
    )


def test_without_primary_use_first_and_ignore_other_scores(
    payload, cve, metric
):
    """Не вибирати максимум та не аналізувати невибраний cvssData."""
    metric["type"] = "Secondary"
    cve["metrics"]["cvssMetricV31"].append({"cvssData": None})
    assert report(payload)["score"] == 9.8


def test_analysis_preserves_inputs_and_has_no_output(payload, capsys):
    """Аналіз не змінює передані словники й нічого не друкує."""
    original = deepcopy(payload)
    record = extract_record(payload, CVE)
    record_copy = deepcopy(record)
    build_report(record, CVE, 8)
    assert payload == original and record == record_copy
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("value", [True, False, 0, 16, 8.0, "8", None])
def test_invalid_variants(value):
    """Не приймати bool, дроби та номери за межами таблиці."""
    with pytest.raises(ValueError):
        validate_variant(value)
    with pytest.raises(ValueError):
        build_report(None, CVE, value)


@pytest.mark.parametrize(
    "value",
    [
        "cve-2021-44228",
        "CVE-21-44228",
        "CVE-2021-123",
        "CVE-2021-44228\n",
        " CVE-2021-44228",
        "",
        None,
    ],
)
def test_cve_requires_full_case_sensitive_match(value):
    """Відхилити частковий збіг, пробіли та неправильний регістр."""
    with pytest.raises(ValueError):
        validate_cve_id(value)


def test_pattern_does_not_validate_calendar_year():
    """Прийняти синтетичний рік, як вимагає методичка."""
    assert validate_cve_id("CVE-0000-10000") == "CVE-0000-10000"

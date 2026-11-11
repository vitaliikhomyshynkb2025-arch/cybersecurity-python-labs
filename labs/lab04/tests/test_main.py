"""Локальний та підмінений мережевий CLI з перевіркою потоків і кодів."""

import importlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from labs.lab04 import analysis, api_client, main

CVE = "CVE-2099-10001"


@pytest.fixture
def input_path(tmp_path, payload):
    """Записати тимчасову локальну відповідь."""
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_local_cli_never_calls_client(input_path, monkeypatch, capsys):
    """Локальний режим формує один JSON без звернення до клієнта."""
    client = Mock(side_effect=AssertionError("HTTP заборонений"))
    monkeypatch.setattr(api_client, "fetch_response", client)
    assert main.main(["--cve", CVE, "--input", str(input_path)]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert captured.err == "" and result["decision"] == "other"
    assert result["variant"] == 8
    client.assert_not_called()


def test_online_cli_with_fake_client(payload, monkeypatch, capsys):
    """Перевірити взаємодію CLI з клієнтом без справжньої мережі."""
    client = Mock(return_value=payload)
    monkeypatch.setattr(api_client, "fetch_response", client)
    assert main.main(["--cve", CVE]) == 0
    assert json.loads(capsys.readouterr().out)["cve_id"] == CVE
    client.assert_called_once_with(CVE)


@pytest.mark.parametrize(
    "status", ["not_found", "insufficient_data", "rejected"]
)
def test_non_review_states_are_success(payload, monkeypatch, capsys, status):
    """Брак даних або відхилення CVE не є помилкою виконання CLI."""
    if status == "not_found":
        payload["vulnerabilities"] = []
    elif status == "rejected":
        payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    else:
        del payload["vulnerabilities"][0]["cve"]["metrics"]
    monkeypatch.setattr(
        api_client, "fetch_response", Mock(return_value=payload)
    )
    assert main.main(["--cve", CVE]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == status


@pytest.mark.parametrize(
    "mode,message",
    [
        ("missing", "не знайдено"),
        ("json", "коректним JSON"),
        ("utf8", "UTF-8"),
        ("structure", "структури даних"),
    ],
)
def test_local_errors(tmp_path, capsys, mode, message):
    """Неправильний файл дає код 1, лише stderr і жодного traceback."""
    path = tmp_path / "invalid.json"
    if mode == "json":
        path.write_text("{", encoding="utf-8")
    elif mode == "utf8":
        path.write_bytes(b"\xff\xfe")
    elif mode == "structure":
        path.write_text("null", encoding="utf-8")
    assert main.main(["--cve", CVE, "--input", str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and message in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "error,message",
    [
        (PermissionError("private path"), "дозволу"),
        (OSError("private path"), "прочитати"),
    ],
)
def test_read_errors_are_safe(monkeypatch, capsys, error, message):
    """Не залежати від прав поточного користувача при тесті PermissionError."""
    monkeypatch.setattr(main, "load_response", Mock(side_effect=error))
    assert main.main(["--cve", CVE, "--input", "fake.json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and message in captured.err
    assert "private path" not in captured.err


def test_client_error_goes_only_to_stderr(monkeypatch, capsys):
    """CLI показує вже очищене повідомлення клієнта без JSON-звіту."""
    monkeypatch.setattr(
        api_client,
        "fetch_response",
        Mock(side_effect=api_client.APIClientError("HTTP-помилка NVD: 429.")),
    )
    assert main.main(["--cve", CVE]) == 1
    assert capsys.readouterr() == ("", "HTTP-помилка NVD: 429.\n")


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--cve", "cve-2021-44228"],
        ["--cve", "CVE-2021-44228\n"],
        ["--cve", CVE, "--variant", "1"],
    ],
)
def test_bad_arguments_exit_two(argv, capsys):
    """Неправильні аргументи обробляє argparse до отримання даних."""
    with pytest.raises(SystemExit) as caught:
        main.main(argv)
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err


@pytest.mark.parametrize("variant", [True, 0, 16, "8", 8.0])
def test_bad_imported_variant_exit_two(monkeypatch, capsys, variant):
    """Підмінити імпортоване ім'я саме в модулі main."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    with pytest.raises(SystemExit) as caught:
        main.main(["--cve", CVE])
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "варіанта" in captured.err


def test_utf8_output_is_not_ascii_escaped(payload, monkeypatch, capsys):
    """Один JSON містить українські літери без послідовностей Unicode."""
    payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "Опис"
    monkeypatch.setattr(
        api_client, "fetch_response", Mock(return_value=payload)
    )
    assert main.main(["--cve", CVE]) == 0
    output = capsys.readouterr().out
    assert "Опис" in output and "\\u041e" not in output


def test_imports_do_not_run_cli_read_data_or_request(monkeypatch, capsys):
    """Повторний імпорт модулів не виконує прикладних операцій."""
    guard = Mock(side_effect=AssertionError("Побічний ефект імпорту"))
    monkeypatch.setattr(Path, "read_text", guard)
    monkeypatch.setattr(api_client.requests, "get", guard)
    for module in (analysis, api_client, main):
        importlib.reload(module)
    guard.assert_not_called()
    assert capsys.readouterr() == ("", "")

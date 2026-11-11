"""Підміна Requests із перевіркою справжньої функції клієнта."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE = "CVE-2099-10001"
SECRET = "made-up-test-key"


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, {}),
        ("", {}),
        (" \t ", {}),
        (f" {SECRET} ", {"apiKey": SECRET}),
    ],
)
def test_headers(monkeypatch, value, expected):
    """Перевірити заголовок apiKey без справжнього ключа."""
    if value is not None:
        monkeypatch.setenv("NVD_API_KEY", value)
    assert (
        api_client.build_headers() == {"Accept": "application/json"} | expected
    )


def test_key_is_read_at_call_time(monkeypatch):
    """Зміна середовища після імпорту впливає на наступний виклик."""
    assert "apiKey" not in api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", SECRET)
    assert api_client.build_headers()["apiKey"] == SECRET


@pytest.fixture
def response():
    """Створити контрольовану відповідь без справжнього транспорту."""
    result = Mock(spec=requests.Response)
    result.status_code = 200
    result.json.return_value = {"vulnerabilities": []}
    return result


def test_fetch_uses_exact_request(monkeypatch, response):
    """Довести один GET, params, таймаут, заголовки та заборону redirect."""
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert api_client.fetch_response(CVE) == {"vulnerabilities": []}
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": CVE},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()
    response.json.assert_called_once_with()


def test_fetch_key_is_only_in_headers(monkeypatch, response):
    """Секрет не включено до URL або params."""
    monkeypatch.setenv("NVD_API_KEY", SECRET)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    api_client.fetch_response(CVE)
    assert fake_get.call_args.kwargs["headers"]["apiKey"] == SECRET
    assert SECRET not in fake_get.call_args.args[0]
    assert fake_get.call_args.kwargs["params"] == {"cveId": CVE}


@pytest.mark.parametrize(
    "error,expected",
    [
        (requests.Timeout(SECRET), "час очікування"),
        (requests.ConnectionError(SECRET), "з'єднання"),
        (requests.RequestException(SECRET), "отримати відповідь"),
    ],
)
def test_network_errors_are_safe(monkeypatch, error, expected):
    """Не розкривати текст винятку навіть за наявності секрету."""
    fake_get = Mock(side_effect=error)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    with pytest.raises(api_client.APIClientError, match=expected) as caught:
        api_client.fetch_response(CVE)
    assert SECRET not in str(caught.value)
    fake_get.assert_called_once()


@pytest.mark.parametrize("status", [400, 404, 429, 500, 503])
def test_http_errors_are_not_empty_search(monkeypatch, response, status):
    """Задати side_effect, бо Mock сам не виконує raise_for_status."""
    response.status_code = status
    response.raise_for_status.side_effect = requests.HTTPError(
        SECRET, response=response
    )
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )
    with pytest.raises(api_client.APIClientError, match=str(status)) as caught:
        api_client.fetch_response(CVE)
    assert SECRET not in str(caught.value)
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [201, 204, 301, 302, 304])
def test_unexpected_status_is_rejected(monkeypatch, response, status):
    """Приймати виключно HTTP 200, включно із забороною 3xx."""
    response.status_code = status
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )
    with pytest.raises(api_client.APIClientError, match=str(status)):
        api_client.fetch_response(CVE)
    response.raise_for_status.assert_called_once_with()
    response.json.assert_not_called()


def test_network_json_decode_error(monkeypatch, response):
    """Відокремити неправильний мережевий JSON від структури даних."""
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )
    with pytest.raises(api_client.APIClientError, match="коректним JSON"):
        api_client.fetch_response(CVE)


def test_fixture_really_blocks_requests():
    """Заборона діє до відкриття мережевого з'єднання."""
    assert not hasattr(requests.sessions.Session, "request")
    with pytest.raises(AttributeError):
        requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0")

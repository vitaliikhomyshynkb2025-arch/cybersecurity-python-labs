"""Один запит Requests до фіксованого NVD CVE API 2.0."""

import os
from typing import Any

import requests

from labs.lab04.analysis import validate_cve_id

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = (3.05, 10)


class APIClientError(RuntimeError):
    """Містити лише безпечне повідомлення без секретів і тіла відповіді."""


def build_headers() -> dict[str, str]:
    """Зчитати необов'язковий ключ у момент виклику та обрізати пробіли."""
    headers = {"Accept": "application/json"}
    key = os.getenv("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Отримати JSON одним GET без повторів і перенаправлень."""
    validate_cve_id(cve_id)
    try:
        response = requests.get(
            API_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        response.raise_for_status()
        if response.status_code != 200:
            raise APIClientError(
                f"Неочікуваний HTTP-статус NVD: {response.status_code}."
            )
        return response.json()
    except requests.exceptions.Timeout:
        raise APIClientError(
            "Перевищено час очікування відповіді NVD."
        ) from None
    except requests.exceptions.ConnectionError:
        raise APIClientError(
            "Не вдалося встановити з'єднання з NVD."
        ) from None
    except requests.exceptions.HTTPError as error:
        status = (
            error.response.status_code
            if error.response is not None
            else "невідомий"
        )
        raise APIClientError(f"HTTP-помилка NVD: {status}.") from None
    except requests.exceptions.JSONDecodeError:
        raise APIClientError("Відповідь NVD не є коректним JSON.") from None
    except requests.exceptions.RequestException:
        raise APIClientError("Не вдалося отримати відповідь NVD.") from None

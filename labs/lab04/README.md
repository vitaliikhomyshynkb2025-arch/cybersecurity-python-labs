# Лабораторна 4 — NVD API та автоматизоване тестування

Хомишин Віталій Вікторович, КБ-208. Варіант **8** зі спільного
`shared/student.py`. Викладач — Синявський О. Ю.

Консольна утиліта читає відповідь NVD CVE API 2.0 або локальний UTF-8 JSON,
перевіряє використані поля та формує один JSON-звіт. ЛР3 і SQLite для її
роботи не потрібні. Імпорти не запускають CLI, HTTP-запитів чи читання даних.

## Встановлення

З кореня репозиторію, Python **3.12 або новіший**:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Перевірено Python 3.12.14, Requests 2.34.2, pytest 9.2.0, Ruff 0.16.8.
Спільний requirements.txt зберігає залежності попередніх робіт.

## Локальний запуск для розроблення та захисту

```sh
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Це **штучний запис**, його не потрібно шукати у NVD. Очікується код 0,
`score=9.8`, `observed="UNCHANGED"`, `decision="other"`.
Наявність `--input` повністю виключає виклик мережевого клієнта.

Правило варіанта: `score >= 9.0` **і одночасно** `scope == "CHANGED"`.
Scope описує, чи може вплив вийти за межі повноважень безпеки вразливого
компонента. У прикладі `UNCHANGED`, тому високого числа недостатньо.
Число і scope завжди беруться з тієї самої вибраної оцінки.

## Один ручний запит до NVD

```sh
python -m labs.lab04.main --cve CVE-2021-44228
```

Адреса фіксована: https://services.nvd.nist.gov/rest/json/cves/2.0.
Один GET передає `params={"cveId": cve_id}`, `timeout=(3.05, 10)` і
`allow_redirects=False`; перевірка TLS залишається ввімкненою.
Автоматичних повторів, завантаження посилань і сканування систем немає.

Ключ не обов'язковий. `build_headers()` під час виклику читає
`NVD_API_KEY`, обрізає крайні пробіли й додає непорожній ключ як заголовок
`apiKey`. Ключ не передається в URL, не друкується і не зберігається.
У тестах використовуються лише вигадані значення.

Одиничний запит **11 листопада 2026, 23:42 за Києвом** дав:
`score=10.0`, `scope="CHANGED"`, `decision="review"`, джерело
`nvd@nist.gov`, CVSS v3.1. Це зафіксований результат, а не незмінний
еталон для тестів: дані NVD можуть оновлюватися.

## Перевірка відповіді та рішення

`extract_record()` перевіряє обгортку, точний CVE, статус, описи та оцінку.
Повертає None або незалежний словник із description, vuln_status,
cvss_version, score, score_source, vector та копією cvss_data.
`build_report()` перевіряє поле правила і формує рішення. Обидві функції
чисті: не звертаються до мережі, файлів, часу або середовища й не змінюють
отриманий payload. Перевірено 15 табличних правил, CLI використовує варіант 8.

Береться перший `Primary` у `cvssMetricV31`, інакше перший елемент.
Інші оцінки не аналізуються. CVSS v3.0/v4.0 не підставляються замість v3.1.
Base score — число 0–10; bool, рядок, NaN та нескінченності відхиляються.
Відсутній ключ і неправильне наявне значення відрізняються.

| decision | Умова |
|---|---|
| not_found | Коректна відповідь із порожнім vulnerabilities |
| rejected | Статус Rejected; оцінки не аналізуються |
| insufficient_data | Відсутній статус, оцінка v3.1 або поле правила |
| review | Оцінка не нижче порога та потрібна ознака збігається |
| other | Даних достатньо, але правило не виконане |

`other` і `insufficient_data` не доводять безпечності. `review` — результат
навчального правила, а не готовий пріоритет усунення для організації.
Це перевірка використаних полів, а не повний валідатор NVD/CVSS JSON-схем.

Завжди повертаються 11 ключів: cve_id, variant, description, vuln_status,
cvss_version, score, score_source, vector, rule, observed, decision.
Об'єкт rule містить threshold, field, expected. Відсутні значення — null.

## Коди завершення та помилки

- **0** — звіт сформовано, також для not_found або insufficient_data.
- **1** — мережева помилка, невдале читання, неправильний JSON або структура.
- **2** — неправильні аргументи або варіант (argparse / SystemExit).

Успіх: лише один JSON у stdout з `ensure_ascii=False`.
Помилка: зрозумілий stderr без traceback, ключа, заголовків, тіла відповіді
чи початкового тексту мережевого винятку. HTTP 404 є помилкою HTTP, а не
порожнім успішним пошуком.

## Тести та Ruff

```sh
python -m pytest labs/lab04/tests -q
python -m ruff check labs/lab04
python -m ruff format --check labs/lab04
# Усі роботи разом:
python -m pytest -q
```

ЛР4: **153 passed**. Увесь репозиторій: **211 passed, 53 subtests passed**.
У conftest автоматично видаляються успадкований ключ і транспортний метод
Requests. Тести клієнта підмінюють `api_client.requests.get`; тести CLI —
функцію клієнта або тимчасовий файл. Справжніх запитів тести не виконують.

Успішний сценарій на межі:

```sh
python -m pytest 'labs/lab04/tests/test_analysis.py::test_variant8_threshold[9.0-CHANGED-review]' -v
```

Помилковий сценарій даних із очікуваним ValueError:

```sh
python -m pytest labs/lab04/tests/test_analysis.py::test_variant_field_is_validated_only_in_build_report -v
```

Обидва тести повинні бути зеленими: другий успішно підтверджує відхилення
неправильних даних. У тимчасовій копії заміна `>=` на `>` спричинила
`1 failed` для рівності 9.0; вихідний правильний код залишився незмінним.

## Файли

- main.py — аргументи, вибір джерела, stdout/stderr, коди завершення.
- api_client.py — заголовки, один GET та безпечні помилки клієнта.
- analysis.py — структура NVD, вибір оцінки, правило, звіт.
- data/nvd_sample.json — спільна синтетична відповідь.
- tests/conftest.py — незалежні фікстури та заборона мережі.
- tests/test_analysis.py — структура, стани, вибір Primary і пороги.
- tests/test_api_client.py — параметри Requests, заголовки, HTTP і JSON.
- tests/test_main.py — аргументи, локальний режим та коди завершення.

## Джерела

- Надана методичка Lab 04.pdf, сторінки 1–14.
- [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities).
- [Правила використання NVD](https://nvd.nist.gov/developers/start-here).
- [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document).
- [Requests](https://requests.readthedocs.io/en/latest/user/quickstart/).
- [pytest monkeypatch](https://docs.pytest.org/en/stable/how-to/monkeypatch.html).

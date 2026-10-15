"""Відтворити 14 сценаріїв методички через curl та окремий Uvicorn."""

import argparse
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlencode

from labs.lab03 import database

REPO = Path(__file__).resolve().parents[2]


def record(code: str, **changes) -> dict:
    """Підготувати навчальний запис без ідентифікатора клієнта."""
    return {
        "code": code,
        "title": "Перевірка відновлення",
        "category_id": 1,
        "value": 70.0,
        "status": "new",
    } | changes


def check(condition: bool, message: str) -> None:
    """Зупинити перевірку, якщо справжній результат не збігся з умовою."""
    if not condition:
        raise AssertionError(message)


def verify(output: Path) -> dict:
    """Перевірити API на тимчасовій базі та залишити фактичні результати."""
    curl = shutil.which("curl")
    if curl is None:
        raise RuntimeError("Для перевірки потрібен curl.")
    output.parent.mkdir(parents=True, exist_ok=True)
    result = {"variant": 8, "checks": [], "requests": []}
    process = None
    server_log = output.with_suffix(".server.log")
    with TemporaryDirectory(prefix="lab03-verify-") as directory:
        environment = os.environ | {
            "LAB03_DB_PATH": str(Path(directory) / "verification.sqlite3")
        }
        runs = []
        for _ in range(2):
            run = subprocess.run(
                [sys.executable, "-m", "labs.lab03.seed"],
                cwd=REPO,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
                timeout=15,
            )
            runs.append(run.stdout.strip())
        result["seed_runs"] = runs
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        base_url = f"http://127.0.0.1:{port}"
        result["base_url"] = base_url

        def request(method, path, expected, body=None, parameters=None):
            url = base_url + path
            if parameters:
                url += "?" + urlencode(parameters)
            command = [
                curl,
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "--write-out",
                "\n%{http_code}",
                "-X",
                method,
                url,
            ]
            if body is not None:
                command.extend(
                    [
                        "-H",
                        "Content-Type: application/json",
                        "--data-binary",
                        json.dumps(body, ensure_ascii=False),
                    ]
                )
            response = subprocess.run(
                command, capture_output=True, text=True, check=True, timeout=15
            )
            text, status = response.stdout.rsplit("\n", 1)
            status = int(status)
            payload = json.loads(text) if text else None
            result["requests"].append(
                {
                    "method": method,
                    "path": path,
                    "parameters": parameters,
                    "body": body,
                    "status": status,
                    "response": payload,
                    "command": shlex.join(command),
                }
            )
            check(
                status == expected, f"{method} {path}: {status} != {expected}"
            )
            if status == 204:
                check(text == "", "204 повинен мати порожнє тіло.")
            return payload

        def codes():
            rows = request("GET", "/records", 200, parameters={"limit": 100})
            return [row["code"] for row in rows]

        def passed(number, title, **evidence):
            result["checks"].append(
                {
                    "number": number,
                    "title": title,
                    "passed": True,
                    **evidence,
                }
            )
            print(f"PASS {number:02d}: {title}", flush=True)

        def stop_server():
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        with server_log.open("w", encoding="utf-8") as log:

            def start_server():
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "labs.lab03.main:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                    ],
                    cwd=REPO,
                    env=environment,
                    stdout=log,
                    stderr=log,
                )
                for _ in range(100):
                    try:
                        with socket.create_connection(
                            ("127.0.0.1", port), 0.1
                        ):
                            return child
                    except OSError:
                        if child.poll() is not None:
                            raise RuntimeError(
                                "Uvicorn не запустився."
                            ) from None
                        time.sleep(0.05)
                child.terminate()
                child.wait(timeout=10)
                raise TimeoutError("Сервер не став доступним.")

            try:
                process = start_server()
                initial = codes()
                categories = request("GET", "/categories", 200)
                check(
                    len(initial) == 8 and len(categories) == 3,
                    "Початкові 3/8.",
                )
                check("пропущено" in runs[1], "Повторний seed не пропущено.")
                passed(
                    1,
                    "Початкове заповнення і повторний seed",
                    categories=3,
                    records=8,
                )

                check(
                    request("GET", "/ping", 200) == {"status": "ok"}, "Ping."
                )
                student = request("GET", "/student", 200)
                check(student["variant_number"] == 8, "Варіант студента.")
                passed(2, "Ping, студент і категорії: HTTP 200")

                created = request("POST", "/records", 201, record("V08-CRUD"))
                path = f"/records/{created['id']}"
                check(request("GET", path, 200) == created, "Читання CRUD.")
                updated = request(
                    "PUT",
                    path,
                    200,
                    record(
                        "V08-CRUD-UPDATED",
                        category_id=2,
                        value=0,
                        status="done",
                    ),
                )
                check(updated["id"] == created["id"], "PUT змінив id.")
                request("DELETE", path, 204)
                request("GET", path, 404)
                passed(3, "Повний CRUD: 201, 200, 200, 204, 404")

                rows = request(
                    "GET", "/records", 200, parameters={"min_value": 60}
                )
                check([row["id"] for row in rows] == [1, 4, 6, 8], "Поріг 60.")
                combined = request(
                    "GET",
                    "/records",
                    200,
                    parameters={
                        "category_id": 1,
                        "status": "new",
                    },
                )
                check(
                    [row["id"] for row in combined] == [1, 4], "Фільтри AND."
                )
                page = request(
                    "GET",
                    "/records",
                    200,
                    parameters={"limit": 2, "offset": 2},
                )
                check([row["id"] for row in page] == [3, 4], "Пагінація.")
                check(
                    request(
                        "GET", "/records", 200, parameters={"category_id": 999}
                    )
                    == [],
                    "Порожній фільтр.",
                )
                passed(
                    4,
                    "Фільтри AND і пагінація",
                    threshold_ids=[1, 4, 6, 8],
                    page_ids=[3, 4],
                )

                before = codes()
                for change in (
                    {"value": -1},
                    {"title": "  "},
                    {"status": "wrong"},
                ):
                    request(
                        "POST",
                        "/records",
                        422,
                        record("V08-INVALID", **change),
                    )
                request("GET", "/records", 422, parameters={"limit": 0})
                check(codes() == before, "422 змінив базу.")
                passed(5, "Неправильні value, title, status і limit: 422")

                request(
                    "POST", "/records", 422, record("V08-TYPE", value="wrong")
                )
                passed(6, "Неправильний тип часу: 422")

                request("GET", "/records/999999", 404)
                request(
                    "POST",
                    "/records",
                    404,
                    record("V08-NO-CAT", category_id=999),
                )
                passed(7, "Відсутній запис і категорія: 404")

                request("POST", "/records", 409, record("V08-01"))
                request("POST", "/categories", 409, {"name": "database"})
                check(codes() == initial, "409 змінив початкові записи.")
                passed(8, "Повторний code і назва категорії: 409")

                request("DELETE", "/categories/1", 409)
                empty = request(
                    "POST", "/categories", 201, {"name": "verification_empty"}
                )
                request("DELETE", f"/categories/{empty['id']}", 204)
                passed(
                    9, "Видалення непорожньої та порожньої категорій: 409/204"
                )

                bulk = request(
                    "POST",
                    "/records/bulk",
                    201,
                    [
                        record("V08-BULK-A"),
                        record("V08-BULK-B", category_id=3),
                    ],
                )
                check(len(codes()) == 10, "Правильний пакет не додано.")
                passed(
                    10,
                    "Правильний пакет із двох записів: 201",
                    before=8,
                    after=10,
                )
                for row in bulk:
                    request("DELETE", f"/records/{row['id']}", 204)

                for number, bad, expected, first_code in (
                    (11, record("V08-01"), 409, "V08-ROLLBACK-DUP"),
                    (
                        12,
                        record("V08-MISSING", category_id=999),
                        404,
                        "V08-ROLLBACK-CAT",
                    ),
                ):
                    before = codes()
                    request(
                        "POST",
                        "/records/bulk",
                        expected,
                        [record(first_code), bad],
                    )
                    after = codes()
                    check(
                        before == after and first_code not in after,
                        "Пакет збережено частково.",
                    )
                    passed(
                        number,
                        f"Відкат пакета: HTTP {expected}",
                        before=len(before),
                        after=len(after),
                        first_code=first_code,
                        first_present=False,
                    )

                before = codes()
                check(
                    request(
                        "GET", "/records", 200, parameters={"q": "' OR 1=1 --"}
                    )
                    == [],
                    "SQL у q виконався.",
                )
                check(codes() == before, "Пошук змінив записи.")
                passed(13, "SQL-ін'єкція обробляється як звичайний текст")

                persistent = request(
                    "POST", "/records", 201, record("V08-PERSIST")
                )
                old_pid = process.pid
                stop_server()
                process = start_server()
                restored = request("GET", f"/records/{persistent['id']}", 200)
                check(restored == persistent, "Перезапуск втратив запис.")
                check(process.pid != old_pid, "Сервер не перезапущено.")
                passed(
                    14,
                    "Запис збережено після справжнього перезапуску Uvicorn",
                    first_pid=old_pid,
                    second_pid=process.pid,
                    code=restored["code"],
                )
                request("DELETE", f"/records/{persistent['id']}", 204)
                check(codes() == initial, "Навчальні дані змінилися.")
            finally:
                stop_server()
    result["all_passed"] = len(result["checks"]) == 14
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    transcript = []
    for item in result["requests"]:
        transcript.extend(
            [
                "$ " + item["command"],
                f"HTTP {item['status']}",
                json.dumps(item["response"], ensure_ascii=False, indent=2)
                if item["response"] is not None
                else "(порожнє тіло)",
                "",
            ]
        )
    output.with_suffix(".txt").write_text("\n".join(transcript))
    print(
        f"Усі 14 сценаріїв пройдено; HTTP-запитів: {len(result['requests'])}."
    )
    print("Демонстраційну базу не змінено; тимчасовий сервер завершено.")
    return result


def main() -> int:
    """Запустити перевірку та обрати шлях збереження доказів."""
    parser = argparse.ArgumentParser(description="14 сценаріїв ЛР3 через curl")
    parser.add_argument(
        "--output",
        type=Path,
        default=database.BASE_DIR / "data" / "verification.json",
    )
    args = parser.parse_args()
    try:
        verify(args.output)
    except (
        OSError,
        RuntimeError,
        AssertionError,
        subprocess.SubprocessError,
    ) as error:
        print(f"Перевірку зупинено: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

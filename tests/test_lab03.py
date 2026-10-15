"""Перевірки API, обмежень SQLite та атомарного збереження ЛР3."""

import io
import json
import sqlite3
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

from labs.lab03 import database, repository, seed
from labs.lab03.main import app


def measurement(code="V08-TEST", **changes):
    """Підготувати незалежне коректне вимірювання для перевірки."""
    record = {
        "code": code,
        "title": "Тестове відновлення",
        "category_id": 1,
        "value": 77.5,
        "status": "new",
    }
    return record | changes


class APITests(unittest.TestCase):
    """Виконати запити до справжнього ASGI-застосунку з окремою базою."""

    def setUp(self):
        """Створити тимчасову базу, не змінюючи демонстраційний файл."""
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        database_patch = patch.object(
            database, "DATABASE_PATH", self.root / "test.sqlite3"
        )
        database_patch.start()
        self.addCleanup(database_patch.stop)
        seed.seed_database()
        self.client = TestClient(app, raise_server_exceptions=False)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def codes(self):
        """Прочитати всі коди без обмеження типової сторінки 20."""
        return [
            row["code"]
            for row in self.client.get(
                "/records", params={"limit": 100}
            ).json()
        ]

    def test_service_endpoints_and_openapi(self):
        """Перевірити студента, категорії, одиниці та описи відповідей."""
        self.assertEqual(self.client.get("/ping").json(), {"status": "ok"})
        student = self.client.get("/student")
        self.assertEqual(student.status_code, 200)
        self.assertEqual(student.json()["variant_number"], 8)
        self.assertEqual(student.json()["group_name"], "КБ-208")
        categories = self.client.get("/categories")
        self.assertEqual(categories.status_code, 200)
        self.assertEqual(
            [row["name"] for row in categories.json()],
            ["database", "web_service", "file_storage"],
        )
        schema = self.client.get("/openapi.json").json()
        self.assertIn("minutes", schema["info"]["description"])
        for route in ("/records", "/records/bulk"):
            self.assertTrue(
                {"201", "404", "409", "422"}.issubset(
                    schema["paths"][route]["post"]["responses"]
                )
            )

    def test_complete_crud_and_empty_delete_response(self):
        """Пройти створення, читання, повну заміну й видалення."""
        created = self.client.post("/records", json=measurement())
        self.assertEqual(created.status_code, 201)
        item = created.json()
        record_id = item["id"]
        self.assertEqual(item["category_name"], "database")
        self.assertEqual(self.client.get(f"/records/{record_id}").json(), item)
        replacement = measurement(
            "V08-CHANGED",
            title="  Нове вимірювання  ",
            category_id=2,
            value=0,
            status="done",
        )
        updated = self.client.put(f"/records/{record_id}", json=replacement)
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["id"], record_id)
        self.assertEqual(updated.json()["title"], "Нове вимірювання")
        self.assertEqual(updated.json()["category_name"], "web_service")
        deleted = self.client.delete(f"/records/{record_id}")
        self.assertEqual((deleted.status_code, deleted.content), (204, b""))
        self.assertEqual(
            self.client.get(f"/records/{record_id}").status_code, 404
        )

    def test_full_put_and_client_id_are_required_correctly(self):
        """Відхиляти частковий PUT, клієнтський id та невідомі поля."""
        before = self.client.get("/records/1").json()
        self.assertEqual(
            self.client.put("/records/1", json={"status": "done"}).status_code,
            422,
        )
        for method, url in (("POST", "/records"), ("PUT", "/records/1")):
            for extra in ({"id": 99}, {"unknown": "value"}):
                response = self.client.request(
                    method, url, json=measurement() | extra
                )
                self.assertEqual(response.status_code, 422)
        self.assertEqual(self.client.get("/records/1").json(), before)

    def test_invalid_values_leave_database_unchanged(self):
        """Відхиляти неправильні типи, межі та нескінченні числа кодом 422."""
        before = self.codes()
        changes = [
            {"value": -1},
            {"value": "wrong"},
            {"value": True},
            {"value": float("inf")},
            {"value": float("nan")},
            {"title": ""},
            {"title": "   "},
            {"title": "x" * 121},
            {"code": "ab"},
            {"code": "x" * 41},
            {"status": "unknown"},
            {"category_id": 0},
            {"category_id": -1},
            {"category_id": 1.5},
            {"category_id": True},
            {"category_id": "1"},
        ]
        for change in changes:
            with self.subTest(change=change):
                response = self.client.post(
                    "/records",
                    content=json.dumps(measurement(**change)),
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(response.status_code, 422)
        self.assertEqual(self.codes(), before)

    def test_filters_and_threshold_include_exactly_sixty(self):
        """Поєднувати фільтри через AND і включати рівність порогу."""
        result = self.client.get("/records", params={"min_value": 60}).json()
        self.assertEqual(
            [row["code"] for row in result],
            [
                "V08-01",
                "V08-04",
                "V08-06",
                "V08-08",
            ],
        )
        combined = self.client.get(
            "/records",
            params={
                "category_id": 1,
                "status": "new",
                "min_value": 60,
            },
        ).json()
        self.assertEqual([row["id"] for row in combined], [1, 4])
        self.assertEqual(
            self.client.get("/records", params={"category_id": 999}).json(), []
        )

    def test_pagination_and_invalid_query_parameters(self):
        """Зберігати порядок сторінок і перевіряти всі параметри списку."""
        result = self.client.get("/records", params={"limit": 2, "offset": 2})
        self.assertEqual([row["id"] for row in result.json()], [3, 4])
        for parameters in (
            {"limit": 0},
            {"limit": 101},
            {"offset": -1},
            {"category_id": 0},
            {"status": "wrong"},
            {"q": ""},
            {"q": "a" * 121},
            {"min_value": -1},
            {"min_value": "wrong"},
            {"min_value": "NaN"},
            {"min_value": "inf"},
        ):
            with self.subTest(parameters=parameters):
                self.assertEqual(
                    self.client.get("/records", params=parameters).status_code,
                    422,
                )

    def test_case_sensitive_literal_search_and_sql_injection(self):
        """Шукати буквальні підрядки, не виконуючи SQL із рядка q."""
        self.client.post(
            "/records", json=measurement(title="Резерв 100%_готово")
        )
        for query in ("%", "_"):
            rows = self.client.get("/records", params={"q": query}).json()
            self.assertEqual([row["code"] for row in rows], ["V08-TEST"])
        self.assertEqual(
            self.client.get("/records", params={"q": "вимірювання"}).json(), []
        )
        self.assertEqual(
            len(
                self.client.get("/records", params={"q": "Вимірювання"}).json()
            ),
            8,
        )
        before = self.codes()
        self.assertEqual(
            self.client.get("/records", params={"q": "' OR 1=1 --"}).json(), []
        )
        self.assertEqual(self.codes(), before)

    def test_missing_resources_and_invalid_path_ids(self):
        """Відрізняти відсутній ресурс 404 від неправильного id 422."""
        for method in ("GET", "DELETE", "PUT"):
            response = self.client.request(
                method, "/records/999", json=measurement()
            )
            self.assertEqual(response.status_code, 404)
        for method, url in (("POST", "/records"), ("PUT", "/records/1")):
            self.assertEqual(
                self.client.request(
                    method, url, json=measurement(category_id=999)
                ).status_code,
                404,
            )
        for path in ("/records/0", "/records/-1", "/records/text"):
            self.assertEqual(self.client.get(path).status_code, 422)
        self.assertEqual(
            self.client.delete("/categories/999").status_code, 404
        )

    def test_unique_codes_and_category_constraints(self):
        """Зберігати унікальність і захищати непорожні категорії."""
        self.assertEqual(
            self.client.post(
                "/records", json=measurement("V08-01")
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.put(
                "/records/1", json=measurement("V08-02")
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.post(
                "/categories", json={"name": "database"}
            ).status_code,
            409,
        )
        self.assertEqual(self.client.delete("/categories/1").status_code, 409)
        created = self.client.post("/categories", json={"name": " backup "})
        self.assertEqual(created.status_code, 201)
        category_id = created.json()["id"]
        self.assertEqual(created.json()["name"], "backup")
        deleted = self.client.delete(f"/categories/{category_id}")
        self.assertEqual((deleted.status_code, deleted.content), (204, b""))
        self.assertEqual(len(self.codes()), 8)

    def test_bulk_success_and_size_validation(self):
        """Зберігати два записи разом і відхиляти пакети поза межами 1–100."""
        rows = [measurement("V08-BULK-A"), measurement("V08-BULK-B")]
        result = self.client.post("/records/bulk", json=rows)
        self.assertEqual(result.status_code, 201)
        self.assertEqual(len(result.json()), 2)
        self.assertTrue(
            all(row["category_name"] == "database" for row in result.json())
        )
        before = self.codes()
        for invalid in (
            [],
            [measurement()] * 101,
            [measurement(), {"code": "x"}],
        ):
            self.assertEqual(
                self.client.post("/records/bulk", json=invalid).status_code,
                422,
            )
        self.assertEqual(self.codes(), before)

    def test_bulk_duplicate_rolls_back_real_insert_in_one_transaction(self):
        """Скасувати вставлений перший елемент після помилки другого."""
        statements = []
        original = database.get_connection

        def traced_connection():
            connection = original()
            connection.set_trace_callback(statements.append)
            return connection

        before = self.codes()
        with patch.object(database, "get_connection", traced_connection):
            result = self.client.post(
                "/records/bulk",
                json=[
                    measurement("V08-ROLLBACK"),
                    measurement("V08-01"),
                ],
            )
        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.codes(), before)
        self.assertNotIn("V08-ROLLBACK", self.codes())
        self.assertTrue(
            any("INSERT INTO records" in sql for sql in statements)
        )
        self.assertEqual(sum(sql.startswith("BEGIN") for sql in statements), 1)
        self.assertIn("ROLLBACK", statements)
        self.assertNotIn("COMMIT", statements)

    def test_bulk_missing_category_rolls_back_all_changes(self):
        """Скасувати перший запис, якщо другий має відсутню категорію."""
        before = self.codes()
        result = self.client.post(
            "/records/bulk",
            json=[
                measurement("V08-ROLLBACK"),
                measurement("V08-NO-CATEGORY", category_id=999),
            ],
        )
        self.assertEqual(result.status_code, 404)
        self.assertEqual(self.codes(), before)

    def test_duplicates_inside_bulk_are_atomic(self):
        """Відхиляти повторення нового коду всередині пакета."""
        before = self.codes()
        result = self.client.post(
            "/records/bulk",
            json=[
                measurement("V08-SAME"),
                measurement("V08-SAME"),
            ],
        )
        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.codes(), before)

    def test_database_error_does_not_leak_details(self):
        """Журналювати технічний збій і повертати загальне повідомлення."""
        with patch.object(
            repository,
            "list_records",
            side_effect=sqlite3.OperationalError("SECRET SQL /private/db"),
        ):
            with self.assertLogs("labs.lab03.errors", level="ERROR"):
                result = self.client.get("/records")
        self.assertEqual(result.status_code, 500)
        self.assertNotIn("SECRET", result.text)
        self.assertNotIn("/private", result.text)

    def test_data_survives_application_restart(self):
        """Створення таблиць під час нового lifespan не стирає записи."""
        created = self.client.post("/records", json=measurement()).json()
        with TestClient(app) as restarted:
            result = restarted.get(f"/records/{created['id']}")
        self.assertEqual(result.json(), created)


class DatabaseTests(unittest.TestCase):
    """Перевірити незалежні обмеження SQLite та початкову транзакцію."""

    def setUp(self):
        """Підготувати порожню базу з готовою схемою."""
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        target = patch.object(
            database, "DATABASE_PATH", self.root / "db.sqlite3"
        )
        target.start()
        self.addCleanup(target.stop)
        database.initialize_database()

    def counts(self):
        """Отримати кількість категорій і записів без HTTP-пагінації."""
        with closing(database.get_connection()) as connection:
            return tuple(
                connection.execute(
                    "SELECT (SELECT count(*) FROM categories), "
                    "(SELECT count(*) FROM records)"
                ).fetchone()
            )

    def test_seed_is_reproducible_and_not_duplicated(self):
        """Додати 3/8 один раз; повторний запуск залишає ті самі дані."""
        self.assertTrue(seed.seed_database())
        self.assertEqual(self.counts(), (3, 8))
        before = repository.list_records()
        self.assertFalse(seed.seed_database())
        database.initialize_database()
        self.assertEqual(repository.list_records(), before)
        self.assertEqual(sum(row["value"] for row in before), 440.0)

    def test_invalid_seed_and_duplicate_seed_leave_empty_database(self):
        """Не залишати навіть категорії після помилки початкового пакета."""
        original = json.loads(seed.SEED_PATH.read_text())
        for invalid_model in (True, False):
            data = json.loads(json.dumps(original))
            if invalid_model:
                data["records"][1]["value"] = -1
                error = ValidationError
            else:
                data["records"][1]["code"] = data["records"][0]["code"]
                error = sqlite3.IntegrityError
            source = self.root / "invalid.json"
            source.write_text(json.dumps(data))
            with self.assertRaises(error):
                seed.seed_database(source)
            self.assertEqual(self.counts(), (0, 0))

    def test_sql_constraints_work_without_pydantic(self):
        """Перевірити ключі, CHECK, UNIQUE та скінченність у SQLite."""
        seed.seed_database()
        with closing(database.get_connection()) as connection:
            self.assertEqual(
                connection.execute("PRAGMA foreign_keys").fetchone()[0], 1
            )
        for changes in (
            {"category_id": 999},
            {"value": -1},
            {"value": float("inf")},
            {"value": float("nan")},
            {"status": "wrong"},
            {"code": "V08-01"},
        ):
            record = measurement(**changes)
            with self.subTest(changes=changes):
                with self.assertRaises(sqlite3.IntegrityError):
                    with database.transaction() as connection:
                        connection.execute(
                            repository.INSERT_RECORD,
                            tuple(
                                record[field] for field in repository.FIELDS
                            ),
                        )
                self.assertEqual(self.counts(), (3, 8))

    def test_connection_is_closed_after_operation(self):
        """Закривати з'єднання після успіху і після rollback."""
        saved = []
        original = database.get_connection

        def capture():
            connection = original()
            saved.append(connection)
            return connection

        with patch.object(database, "get_connection", capture):
            repository.create_category("one")
            with self.assertRaises(sqlite3.IntegrityError):
                repository.create_category("one")
        for connection in saved:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_seed_cli_reports_missing_source_without_traceback(self):
        """Повертати зрозумілу відмову для відсутнього JSON."""
        output = io.StringIO()
        with patch(
            "sys.argv", ["seed", "--source", str(self.root / "absent")]
        ):
            with redirect_stdout(output):
                code = seed.main()
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", output.getvalue())


if __name__ == "__main__":
    unittest.main()

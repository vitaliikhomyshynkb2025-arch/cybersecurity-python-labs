"""Перевірки меж, пріоритетів доступу та збереження даних."""

import hashlib
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from labs.lab01 import task1, task2, task3
from labs.lab01.variant import CRITERIA, FORBIDDEN_PASSWORDS, PASSWORDS


class LabTests(unittest.TestCase):
    """Перевірити вимоги на контрольованих вхідних даних."""

    def setUp(self):
        """Ізолювати файли кожного тесту від демонстраційної бази."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.patch = patch.object(task3, "DATA_DIR", Path(self.temp.name))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        task3.users_db.clear()

    def test_duplicates(self):
        """Додати рівно три копії без зміни початкового списку."""
        result, indices = task1.add_duplicates(PASSWORDS, 8)
        self.assertEqual(len(result), 13)
        self.assertEqual(len(set(indices)), 3)
        self.assertEqual(result[10:], [PASSWORDS[i] for i in indices])
        self.assertEqual(len(PASSWORDS), 10)

    def test_password_categories(self):
        """Перевірити всі категорії та обидві межі довжини."""
        cases = {
            "Abcdef1!x": "Заборонений",
            "abcdefghij": "Слабкий",
            "Abcdefghij": "Середній",
            "Abcdefgh1!": "Сильний",
            "Abcdefghijk1!": "Сильний",
            "Abcdefghijkl1!": "Дуже сильний",
            "only-forbidden": "Заборонений",
        }
        for password, expected in cases.items():
            with self.subTest(password=password):
                actual = task1.evaluate_password(
                    password,
                    Counter([password]),
                    CRITERIA,
                    FORBIDDEN_PASSWORDS | {"only-forbidden"},
                )
                self.assertEqual(actual, expected)

    def test_long_duplicate(self):
        """Повторний довгий пароль не може бути дуже сильним."""
        password = "Abcdefghijkl1!"
        self.assertEqual(
            task1.evaluate_password(
                password, Counter([password, password]), CRITERIA, set()
            ),
            "Сильний",
        )

    def test_access_priority(self):
        """Блокування переважає активність і максимальний допуск."""
        users = {"a": {"active": False, "clearance": 4}}
        resource = ("r", 1)
        self.assertEqual(
            task2.check_access("x", resource, users, {"x"}),
            "DENY (User not found)",
        )
        self.assertEqual(
            task2.check_access("a", resource, users, {"a"}),
            "DENY (User is blocked)",
        )
        self.assertEqual(
            task2.check_access("a", resource, users, set()),
            "DENY (Account inactive)",
        )

    def test_clearance(self):
        """Рівність допуску достатня, нижчий допуск відхиляється."""
        users = {"a": {"active": True, "clearance": 2}}
        self.assertEqual(
            task2.check_access("a", ("r", 2), users, set()), "ALLOW"
        )
        self.assertEqual(
            task2.check_access("a", ("r", 3), users, set()),
            "DENY (Insufficient clearance)",
        )

    def test_hash_vector(self):
        """Хеш відповідає SHA-256 саме password + salt."""
        password = "abcdefghijk"
        expected = hashlib.sha256(b"abcdefghijk00008").hexdigest()
        self.assertEqual(task3.generate_hash(password, "00008"), expected)
        self.assertEqual(len(expected), 64)
        self.assertNotEqual(expected, task3.generate_hash(password))

    def test_hash_validation(self):
        """Порожні значення і короткий пароль дають різні винятки."""
        for password, salt in [
            (None, "s"),
            ("", "s"),
            ("longpassword", None),
            ("longpassword", ""),
        ]:
            with self.assertRaises(ValueError):
                task3.generate_hash(password, salt)
        with self.assertRaises(task3.ValidationError):
            task3.generate_hash("abcdefghij")

    def test_csv_roundtrip(self):
        """Відновити 10 записів без збереження відкритих паролів."""
        task3.create_users(task3.USERS_TO_REGISTER)
        rows = task3.read_users()
        self.assertEqual(len(rows), 10)
        text = (task3.DATA_DIR / "users.csv").read_text()
        self.assertNotIn("Study@Python", text)
        self.assertEqual(rows[0][0], "student01")

    def test_login_and_logs(self):
        """Залогувати позиційні й іменовані виклики та винятки."""
        task3.create_users(task3.USERS_TO_REGISTER)
        task3.users_db[:] = task3.read_users()
        self.assertTrue(task3.login("student01", "Study@Python01"))
        self.assertFalse(
            task3.login(username="student01", password="WrongPass01!")
        )
        self.assertFalse(task3.login("unknown", "Study@Python01"))
        with self.assertRaises(ValueError):
            task3.login("", "Study@Python01")
        with self.assertRaises(task3.ValidationError):
            task3.login("student01", "short")
        text = (task3.DATA_DIR / "log.json").read_text()
        events = json.loads(text)
        self.assertEqual(
            [e["result"] for e in events], ["success"] + ["failure"] * 4
        )
        self.assertTrue(
            all(e["args"] == [] and e["kwargs"] == {} for e in events)
        )
        self.assertNotIn("Study@Python", text)
        self.assertNotIn("WrongPass", text)
        self.assertNotIn("short", text)
        self.assertEqual(task3.login.__name__, "login")

    def test_duplicate_username(self):
        """Відхилити повторний логін до запису бази."""
        with self.assertRaises(task3.ValidationError):
            task3.create_users((("a", "longpassword"), ("a", "otherpassword")))
        self.assertFalse((task3.DATA_DIR / "users.csv").exists())

    def test_missing_and_malformed_csv(self):
        """Відсутній і пошкоджений CSV не дають доступу."""
        with self.assertRaises(FileNotFoundError):
            task3.read_users()
        (task3.DATA_DIR / "users.csv").write_text("broken,row,extra")
        with self.assertRaises(task3.ValidationError):
            task3.read_users()

    def test_bad_log_not_overwritten(self):
        """Не затирати пошкоджений журнал новими подіями."""
        path = task3.DATA_DIR / "log.json"
        path.write_text("broken json")
        with self.assertRaises(ValueError):
            task3.login("unknown", "longpassword")
        self.assertEqual(path.read_text(), "broken json")

    def test_log_permission_error(self):
        """Відсутність дозволу запису перериває вхід."""
        with patch.object(task3, "append_event", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                task3.login("unknown", "longpassword")


if __name__ == "__main__":
    unittest.main()

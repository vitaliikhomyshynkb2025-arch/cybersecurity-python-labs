"""Перевірки автентифікації, таймаутів, DNS-правил і помилок CLI."""

import csv
import io
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from labs.lab02 import main, task1, task2

REPO = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 8, 9, 0, tzinfo=timezone.utc)
HEADER = "Timestamp,ClientIP,Domain,QueryType\n"


class UserTests(unittest.TestCase):
    """Перевірити правила профілю та захист параметрів пароля."""

    def test_email_boundaries_and_atomic_setter(self):
        """Приймати 3–64 символи й зберігати адресу після відмови."""
        user = task1.User("student", "abc@example.org")
        user.email = "a" * 64 + "@example.org"
        for invalid in (
            "ab@example.org",
            "a" * 65 + "@example.org",
            "1abc@example.org",
            "abc@example",
            "abc@-bad.org",
            "abc.def@example.org",
            None,
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    user.email = invalid
                self.assertEqual(user.email, "a" * 64 + "@example.org")

    def test_password_verification_and_replacement(self):
        """Приймати правильний пароль і відхиляти старий після зміни."""
        user = task1.User("student", "abc@example.org")
        self.assertFalse(user.check_password("Study@Python02"))
        user.set_password("Study@Python02")
        self.assertTrue(user.check_password("Study@Python02"))
        self.assertFalse(user.check_password("Wrong@Python02"))
        user.set_password("Changed@Python02")
        self.assertFalse(user.check_password("Study@Python02"))
        self.assertTrue(user.check_password("Changed@Python02"))

    def test_equal_passwords_get_distinct_salts_and_hashes(self):
        """Довести різницю з однаковою сіллю в ЛР1."""
        first = task1.User("first", "first@example.org")
        second = task1.User("second", "second@example.org")
        first.set_password("Equal@Password02")
        second.set_password("Equal@Password02")
        self.assertNotEqual(
            first._User__password_salt, second._User__password_salt
        )
        self.assertNotEqual(
            first._User__password_hash, second._User__password_hash
        )
        self.assertEqual(len(first._User__password_salt), 16)
        self.assertNotIn("Equal@Password02", str(first))
        self.assertFalse(hasattr(first, "__password_hash"))

    def test_blank_password_is_rejected(self):
        """Не встановлювати порожній пароль."""
        user = task1.User("student", "abc@example.org")
        for value in ("", "   ", None):
            with self.assertRaises(ValueError):
                user.set_password(value)

    def test_admin_permissions_are_independent_and_unique(self):
        """Мати окремі множини прав без дублікатів."""
        first = task1.Admin("first", "first@example.org")
        second = task1.Admin("second", "second@example.org")
        first.grant_permission("read")
        first.grant_permission("read")
        self.assertEqual(first.permissions, {"read"})
        self.assertFalse(second.has_permission("read"))
        self.assertIsInstance(first, task1.User)
        first.revoke_permission("read")
        self.assertFalse(first.has_permission("read"))


class AccountTests(unittest.TestCase):
    """Перевірити сесії й аудит на керованому часі без очікування."""

    def setUp(self):
        """Створити профіль зі справжнім PBKDF2-хешем."""
        self.user = task1.User("student", "abc@example.org")
        self.user.set_password("Study@Python02")
        self.account = task1.UserAccount(self.user)

    def test_login_failure_success_and_logout_are_audited(self):
        """Створювати сеанс тільки після успіху та фіксувати результати."""
        self.assertFalse(
            self.account.login("missing", "Study@Python02", "10.0.0.8")
        )
        self.assertIsNone(self.account.session)
        self.assertTrue(
            self.account.login("student", "Study@Python02", "10.0.0.8")
        )
        self.assertTrue(self.account.is_authenticated())
        self.account.logout()
        self.assertFalse(self.account.is_authenticated())
        records = self.account.audit_log.records
        self.assertEqual(
            [x.action for x in records],
            ["login_failure", "login_success", "logout"],
        )
        self.assertTrue(
            all(x.timestamp.utcoffset() == timedelta(0) for x in records)
        )
        self.assertNotIn("Study@Python02", repr(records))

    def test_failed_relogin_clears_existing_session(self):
        """Не залишати чинний сеанс після невдалого повторного входу."""
        self.account.login("student", "Study@Python02", "10.0.0.8")
        self.assertFalse(self.account.login("student", "wrong", "10.0.0.8"))
        self.assertIsNone(self.account.session)

    def test_deactivation_denies_existing_session_and_new_login(self):
        """Відмовляти деактивованому користувачу незалежно від пароля."""
        self.account.login("student", "Study@Python02", "10.0.0.8")
        self.user.deactivate()
        self.assertFalse(self.account.is_authenticated())
        self.assertFalse(
            self.account.login("student", "Study@Python02", "10.0.0.8")
        )

    def test_timeout_boundary_does_not_refresh_activity(self):
        """899 секунд дозволено, рівно 900 — відмова без touch()."""
        session = task1.Session("10.0.0.8", NOW)
        self.account["session"] = session
        with patch.object(task1, "datetime", wraps=datetime) as clock:
            clock.now.return_value = NOW + timedelta(seconds=899)
            self.assertTrue(self.account.is_authenticated())
            clock.now.return_value = NOW + timedelta(seconds=900)
            self.assertFalse(self.account.is_authenticated())
        self.assertEqual(session.last_activity, NOW)

    def test_timeout_and_ip_validation(self):
        """Відхиляти непозитивний таймаут і некоректний IP."""
        session = task1.Session("::1")
        for timeout in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                session.is_active(timeout)
        with self.assertRaises(ValueError):
            task1.Session("999.0.0.1")
        with self.assertRaises(ValueError):
            task1.Session("127.0.0.1", NOW.replace(tzinfo=None))

    def test_component_keys_and_type_validation(self):
        """Приховувати хеш і сіль та очищати сеанс при заміні user."""
        self.assertIs(self.account["user"], self.user)
        for key in ("unknown", "__password_hash", "_User__password_salt"):
            with self.assertRaises(KeyError):
                self.account[key]
            with self.assertRaises(KeyError):
                self.account[key] = "secret"
        for key in ("user", "session", "audit_log"):
            with self.assertRaises(TypeError):
                self.account[key] = "invalid"
        self.account["session"] = task1.Session("10.0.0.8")
        self.account["user"] = task1.User("new", "new@example.org")
        self.assertIsNone(self.account.session)


class DNSTests(unittest.TestCase):
    """Перевірити межі евристик, формат даних та безпечний експорт."""

    def setUp(self):
        """Створити тимчасові файли, незалежні від локального архіву."""
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.csv = self.root / "dns.csv"
        self.blacklist = self.root / "blacklist.txt"
        self.output = self.root / "out.csv"
        self.blacklist.write_text("bad.example.org\n", encoding="utf-8")

    def rows(self, domains):
        """Записати коректні транзакції для заданих доменів."""
        self.csv.write_text(
            HEADER
            + "".join(
                f"2026-09-27T08:00:01,10.0.0.8,{domain},{kind}\n"
                for domain, kind in domains
            ),
            encoding="utf-8",
        )

    def test_blacklist_matches_subdomains_but_not_similar_names(self):
        """Порівнювати DNS-мітки замість довільного суфікса рядка."""
        self.rows(
            [
                ("BAD.EXAMPLE.ORG.", "a"),
                ("x.bad.example.org", "A"),
                ("notbad.example.org", "A"),
            ]
        )
        result = task2.analyze(self.csv, self.blacklist, 30)
        self.assertEqual(result.total, 3)
        self.assertEqual(len(result.alerts), 2)
        self.assertEqual(result.reasons["BLACKLIST"], 2)

    def test_length_boundary_and_service_labels(self):
        """Відрізняти 29 і 30 символів та приймати _dmarc."""
        self.rows(
            [
                ("a" * 29 + ".example.org", "A"),
                ("b" * 30 + ".example.org", "AAAA"),
                ("_dmarc.example.org", "TXT"),
            ]
        )
        result = task2.analyze(self.csv, self.blacklist, 30)
        self.assertEqual(len(result.alerts), 1)
        self.assertEqual(result.alerts[0].reasons, ("LONG_LABEL",))
        self.assertEqual(
            dict(result.query_types), {"A": 1, "AAAA": 1, "TXT": 1}
        )

    def test_multiple_reasons_export_exactly_one_csv_row(self):
        """Не дублювати запит із кількома ознаками."""
        domain = "x" * 64 + ".top"
        self.rows([(domain, "TXT")])
        self.blacklist.write_text(domain, encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            result = task2.run_analysis(
                self.csv, self.blacklist, self.output, 30
            )
        self.assertEqual(len(result.alerts[0].reasons), 4)
        with self.output.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["Reasons"].split(";")), 4)

    def test_bad_rows_are_counted_without_losing_good_rows(self):
        """Пропускати неправильні IP, час і кількість колонок."""
        self.rows([("example.org", "MX")])
        with self.csv.open("a", encoding="utf-8") as stream:
            stream.write("wrong,10.0.0.8,example.org,A\n")
            stream.write("2026-09-27T08:00:01,999.0.0.1,example.org,A\n")
            stream.write("2026-09-27T08:00:01,10.0.0.8,example.org,A,extra\n")
        with self.assertLogs("lab02", level="WARNING"):
            result = task2.analyze(self.csv, self.blacklist, 30)
        self.assertEqual((result.total, result.skipped), (1, 3))

    def test_missing_header_empty_file_and_missing_input(self):
        """Відмовляти при відсутніх або непридатних джерелах."""
        for content in ("", "wrong,header\n", HEADER):
            self.csv.write_text(content, encoding="utf-8")
            with self.assertRaises(ValueError):
                task2.analyze(self.csv, self.blacklist, 30)
        with self.assertRaises(FileNotFoundError):
            task2.analyze(self.root / "missing.csv", self.blacklist, 30)

    def test_input_cannot_be_overwritten_even_through_links(self):
        """Зберігати вхідний CSV при неправильному шляху результату."""
        self.rows([("example.org", "A")])
        original = self.csv.read_bytes()
        with self.assertRaises(ValueError):
            task2.run_analysis(self.csv, self.blacklist, self.csv, 30)
        link = self.root / "link.csv"
        link.symlink_to(self.csv)
        with self.assertRaises(ValueError):
            task2.validate_output(link, (self.csv,))
        self.assertEqual(self.csv.read_bytes(), original)

    def test_no_alerts_produces_header_only(self):
        """Експортувати валідний порожній результат без ділення на нуль."""
        self.rows([("example.org", "A")])
        result = task2.analyze(self.csv, self.blacklist, 30)
        task2.write_alerts(self.output, result.alerts)
        with self.output.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(reader.fieldnames, list(task2.OUTPUT_FIELDS))
            self.assertEqual(list(reader), [])

    def test_failed_export_keeps_previous_report_and_cleans_temp(self):
        """Не пошкоджувати попередній результат при помилці заміни."""
        self.output.write_text("previous", encoding="utf-8")
        with patch.object(Path, "replace", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                task2.write_alerts(self.output, [])
        self.assertEqual(self.output.read_text(), "previous")
        self.assertEqual(list(self.root.glob(".dns-alerts-*.tmp")), [])


class CLITests(unittest.TestCase):
    """Перевірити коди завершення та відсутність дій при імпорті."""

    def test_positive_integer_and_subcommand_validation(self):
        """Відхиляти неправильний поріг до запуску аналізу."""
        self.assertEqual(main.positive_integer("30"), 30)
        for value in ("0", "-1", "abc"):
            with self.assertRaises(main.argparse.ArgumentTypeError):
                main.positive_integer(value)
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main.build_parser().parse_args([])
        self.assertEqual(error.exception.code, 2)

    def test_import_has_no_output(self):
        """Імпорт модулів не запускає демонстрацію чи аналіз."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import labs.lab02.task1; import labs.lab02.main",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr), (0, "", "")
        )

    def test_missing_file_is_reported_without_traceback(self):
        """Показати коротку помилку і повернути код 1."""
        with TemporaryDirectory() as directory:
            missing = str(Path(directory) / "absent.csv")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "labs.lab02.main",
                    "analyze",
                    "--dns-log",
                    missing,
                    "--blacklist",
                    missing,
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FileNotFoundError", result.stdout)
        self.assertNotIn("Traceback", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

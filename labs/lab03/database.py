"""З'єднання SQLite, готова схема та транзакції з явним закриттям."""

import os
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = (
    Path(os.environ.get("LAB03_DB_PATH", BASE_DIR / "data" / "lab3.sqlite3"))
    .expanduser()
    .resolve()
)
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_connection() -> sqlite3.Connection:
    """Відкрити окреме з'єднання з перевіркою зовнішніх ключів."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.row_factory = sqlite3.Row
        return connection
    except sqlite3.Error:
        connection.close()
        raise


def initialize_database() -> None:
    """Створити таблиці готовим скриптом, не змінюючи наявних даних."""
    script = SCHEMA_PATH.read_text(encoding="utf-8")
    with closing(get_connection()) as connection:
        try:
            connection.executescript(script)
        except sqlite3.Error:
            connection.rollback()
            raise


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """Підтвердити всі зміни або скасувати їх та закрити з'єднання."""
    with closing(get_connection()) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            yield connection


if __name__ == "__main__":
    initialize_database()

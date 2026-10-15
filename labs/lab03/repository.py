"""Параметризовані SQL-операції без залежності від FastAPI."""

import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import closing
from typing import Any

from labs.lab03 import database

RecordData = Mapping[str, Any]
FIELDS = ("code", "title", "category_id", "value", "status")
SELECT_RECORD = (
    "SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, "
    "c.name AS category_name FROM records AS r "
    "JOIN categories AS c ON c.id = r.category_id"
)
INSERT_RECORD = (
    "INSERT INTO records (code, title, category_id, value, status) "
    "VALUES (?, ?, ?, ?, ?)"
)


class MissingResource(LookupError):
    """Повідомити, що запис або потрібна категорія не існує."""


def list_categories() -> list[dict]:
    """Отримати категорії у стабільному порядку id."""
    with closing(database.get_connection()) as connection:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT id, name FROM categories ORDER BY id"
            )
        ]


def create_category(name: str) -> dict:
    """Додати категорію, ідентифікатор якої створить SQLite."""
    with database.transaction() as connection:
        cursor = connection.execute(
            "INSERT INTO categories (name) VALUES (?)", (name,)
        )
        return {"id": cursor.lastrowid, "name": name}


def require_category(connection: sqlite3.Connection, category_id: int) -> None:
    """Перевірити категорію всередині поточної транзакції."""
    row = connection.execute(
        "SELECT id FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise MissingResource("Категорію не знайдено.")


def delete_category(category_id: int) -> None:
    """Видалити категорію; зовнішній ключ захищає непорожню."""
    with database.transaction() as connection:
        require_category(connection, category_id)
        connection.execute(
            "DELETE FROM categories WHERE id = ?", (category_id,)
        )


def read_record(connection: sqlite3.Connection, record_id: int) -> dict:
    """Прочитати запис через JOIN у поточному з'єднанні."""
    row = connection.execute(
        SELECT_RECORD + " WHERE r.id = ?", (record_id,)
    ).fetchone()
    if row is None:
        raise MissingResource("Запис не знайдено.")
    return dict(row)


def get_record(record_id: int) -> dict:
    """Прочитати запис та закрити окреме з'єднання."""
    with closing(database.get_connection()) as connection:
        return read_record(connection, record_id)


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Поєднати фіксовані SQL-фільтри через AND і передати значення окремо."""
    clauses, parameters = [], []
    for clause, value in (
        ("r.category_id = ?", category_id),
        ("r.status = ?", status),
        ("r.value >= ?", min_value),
        ("instr(r.title, ?) > 0", q),
    ):
        if value is not None:
            clauses.append(clause)
            parameters.append(value)
    query = SELECT_RECORD
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY r.id LIMIT ? OFFSET ?"
    parameters.extend((limit, offset))
    with closing(database.get_connection()) as connection:
        return [dict(row) for row in connection.execute(query, parameters)]


def insert_records(
    connection: sqlite3.Connection, records: Sequence[RecordData]
) -> list[dict]:
    """Додати пакет у транзакції викликача без окремих commit()."""
    created = []
    for record in records:
        require_category(connection, record["category_id"])
        cursor = connection.execute(
            INSERT_RECORD, tuple(record[field] for field in FIELDS)
        )
        created.append(read_record(connection, cursor.lastrowid))
    return created


def create_records(records: Sequence[RecordData]) -> list[dict]:
    """Зберегти весь пакет або скасувати всі його вставлення."""
    with database.transaction() as connection:
        return insert_records(connection, records)


def replace_record(record_id: int, record: RecordData) -> dict:
    """Замінити всі змінювані поля, зберігши id запису."""
    with database.transaction() as connection:
        read_record(connection, record_id)
        require_category(connection, record["category_id"])
        connection.execute(
            "UPDATE records SET code = ?, title = ?, category_id = ?, "
            "value = ?, status = ? WHERE id = ?",
            (*tuple(record[field] for field in FIELDS), record_id),
        )
        return read_record(connection, record_id)


def delete_record(record_id: int) -> None:
    """Видалити запис або повідомити про відсутній id."""
    with database.transaction() as connection:
        cursor = connection.execute(
            "DELETE FROM records WHERE id = ?", (record_id,)
        )
        if cursor.rowcount == 0:
            raise MissingResource("Запис не знайдено.")

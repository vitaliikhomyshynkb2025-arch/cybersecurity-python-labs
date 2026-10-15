"""Перевірка JSON та атомарне заповнення порожньої бази."""

import argparse
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from labs.lab03 import database, repository
from labs.lab03.schemas import SeedData

SEED_PATH = database.BASE_DIR / "data" / "seed.json"


def seed_database(source: Path = SEED_PATH) -> bool:
    """Додати весь набір один раз; непорожню базу залишити без змін."""
    data = SeedData.model_validate_json(source.read_text(encoding="utf-8"))
    database.initialize_database()
    with database.transaction() as connection:
        occupied = connection.execute(
            "SELECT (SELECT count(*) FROM categories) "
            "+ (SELECT count(*) FROM records)"
        ).fetchone()[0]
        if occupied:
            return False
        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(item.id, item.name) for item in data.categories],
        )
        repository.insert_records(
            connection, [record.model_dump() for record in data.records]
        )
    return True


def main() -> int:
    """Заповнити базу або показати зрозумілу причину відмови."""
    parser = argparse.ArgumentParser(
        description="Початкові дані ЛР3, варіант 8"
    )
    parser.add_argument("--source", type=Path, default=SEED_PATH)
    args = parser.parse_args()
    try:
        inserted = seed_database(args.source)
    except (
        OSError,
        sqlite3.Error,
        ValidationError,
        repository.MissingResource,
    ):
        print("Не вдалося заповнити базу: перевірте JSON, дані та доступ.")
        return 1
    if inserted:
        print("Варіант 8: додано 3 категорії та 8 записів; одиниця — minutes.")
    else:
        print("База вже містить дані. Повторне заповнення пропущено без змін.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

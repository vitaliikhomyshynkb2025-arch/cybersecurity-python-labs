"""Навчальні SHA-256, CSV-база та журнал авторизації без паролів."""

import csv
import hashlib
import hmac
import json
from datetime import datetime
from functools import wraps
from pathlib import Path

from labs.lab01.variant import HASH_ALGORITHM, HASH_MIN_LENGTH
from shared.student import VARIANT_NUMBER

DATA_DIR = Path(__file__).resolve().parent / "data"
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"
USERS_TO_REGISTER = (
    ("student01", "Study@Python01"),
    ("student02", "Study@Python02"),
    ("student03", "Study@Python03"),
    ("student04", "Study@Python04"),
    ("student05", "Study@Python05"),
    ("student06", "Study@Python06"),
    ("student07", "Study@Python07"),
    ("student08", "Study@Python08"),
    ("student09", "Study@Python09"),
    ("student10", "Study@Python10"),
)
users_db = []


class ValidationError(Exception):
    """Пароль або структура бази не відповідає вимогам."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Обчислити SHA-256 від UTF-8 подання password + salt."""
    if password is None or password == "" or salt is None or salt == "":
        raise ValueError("Пароль і сіль не можуть бути порожніми.")
    if len(password) < HASH_MIN_LENGTH:
        raise ValidationError(f"Мінімальна довжина: {HASH_MIN_LENGTH}.")
    return hashlib.new(HASH_ALGORITHM, (password + salt).encode()).hexdigest()


def create_user(username, password):
    """Повернути логін і хеш із персональною сіллю."""
    if not username or not username.strip():
        raise ValueError("Логін не може бути порожнім.")
    return username, generate_hash(password, PERSONAL_SALT)


def create_users(users_list):
    """Перевірити весь набір і записати CSV без відкритих паролів."""
    rows = [
        create_user(username, password) for username, password in users_list
    ]
    if len({row[0] for row in rows}) != len(rows):
        raise ValidationError("Логіни мають бути унікальними.")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with (DATA_DIR / "users.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        csv.writer(file).writerows(rows)
    return rows


def read_users():
    """Зчитати та перевірити навчальну базу перед входом."""
    with (DATA_DIR / "users.csv").open(encoding="utf-8", newline="") as file:
        rows = list(csv.reader(file))
    names = set()
    for row in rows:
        if len(row) != 2:
            raise ValidationError("Некоректна кількість полів CSV.")
        username, hash_value = row
        if not username or username in names:
            raise ValidationError("Порожній або повторний логін у CSV.")
        if len(hash_value) != 64 or any(
            c not in "0123456789abcdef" for c in hash_value
        ):
            raise ValidationError("Некоректний SHA-256 у CSV.")
        names.add(username)
    return rows


def append_event(username, result):
    """Додати подію до JSON-масиву без аргументів із паролями."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "log.json"
    try:
        with path.open(encoding="utf-8") as file:
            events = json.load(file)
    except FileNotFoundError:
        events = []
    if not isinstance(events, list):
        raise ValueError("Журнал повинен містити JSON-масив.")
    events.append(
        {
            "event": "login",
            "user": username,
            "result": result,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "args": [],
            "kwargs": {},
        }
    )
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(events, file, ensure_ascii=False, indent=2)
    temporary.replace(path)


def log_event(function):
    """Залогувати успіх, відмову або помилку валідації входу."""

    @wraps(function)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "")
        result = "failure"
        try:
            success = function(*args, **kwargs)
            result = "success" if success else "failure"
            return success
        finally:
            append_event(username, result)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевірити облікові дані в зчитаному списку users_db."""
    # Реєстрація і вхід мають єдину перевірку даних та хешування.
    username, hash_value = create_user(username, password)
    for stored_username, stored_hash in users_db:
        if stored_username == username:
            return hmac.compare_digest(hash_value, stored_hash)
    return False


def run():
    """Створити 10 навчальних облікових записів і виконати 5 входів."""
    print(
        f"\nЗавдання 3 | {HASH_ALGORITHM.upper()} | "
        f"min_length={HASH_MIN_LENGTH} | salt={PERSONAL_SALT}"
    )
    try:
        create_users(USERS_TO_REGISTER)
        users_db[:] = read_users()
        print(f"{'Логін':<14} SHA-256")
        for username, hash_value in users_db:
            print(f"{username:<14} {hash_value}")
    except FileNotFoundError:
        print("Базу не знайдено.")
        return False
    except PermissionError:
        print("Немає дозволу на роботу з базою.")
        return False
    except (IOError, ValidationError, ValueError) as error:
        print(f"Не вдалося підготувати базу: {type(error).__name__}.")
        return False
    attempts = (
        ("student01", "Study@Python01"),
        ("student01", "WrongPassword!"),
        ("unknown", "Study@Python01"),
        ("", "Study@Python01"),
        ("student01", "short"),
    )
    completed = True
    for username, password in attempts:
        try:
            result = login(username, password)
            print(f"login({username!r}) -> {result}")
        except ValidationError:
            print(f"login({username!r}) -> ValidationError")
        except ValueError:
            print(f"login({username!r}) -> ValueError")
        except FileNotFoundError:
            print("Файл журналу недоступний.")
            completed = False
        except PermissionError:
            print("Немає дозволу на запис журналу.")
            completed = False
        except IOError:
            print("Помилка читання або запису журналу.")
            completed = False
    return completed

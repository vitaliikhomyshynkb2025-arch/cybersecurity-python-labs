"""Оцінювання навчального списку паролів і повторного використання."""

import random
import string
from collections import Counter

from labs.lab01.variant import CRITERIA, FORBIDDEN_PASSWORDS, PASSWORDS
from shared.student import STUDENT_NAME, VARIANT_NUMBER


def add_duplicates(passwords, seed=None):
    """Додати три паролі за різними випадковими індексами оригіналу."""
    indices = random.Random(seed).sample(range(len(passwords)), 3)
    return passwords + [passwords[index] for index in indices], indices


def evaluate_password(password, counts, criteria, forbidden):
    """Визначити категорію за довжиною, групами символів і повторами."""
    if password in forbidden or len(password) < criteria["min_length"]:
        return "Заборонений"
    checks = {
        "require_digits": any(char.isdigit() for char in password),
        "require_upper": any(char.isupper() for char in password),
        "require_special": any(
            char in string.punctuation for char in password
        ),
    }
    required = [value for key, value in checks.items() if criteria[key]]
    if all(required):
        if (
            len(password) >= criteria["min_length"] + 4
            and counts[password] == 1
        ):
            return "Дуже сильний"
        return "Сильний"
    groups = sum(checks.values()) + any(char.islower() for char in password)
    return "Середній" if groups >= 2 else "Слабкий"


def run(seed=None):
    """Показати аналіз усіх 13 паролів і повернути результати."""
    print(f"\nЗавдання 1 | {STUDENT_NAME} | Варіант {VARIANT_NUMBER}")
    passwords, indices = add_duplicates(PASSWORDS, seed)
    counts = Counter(passwords)
    print(f"Індекси дублікатів (від 0): {indices}")
    print(f"{'Пароль':<23} {'Довжина':<8} {'Повтори':<8} Рівень")
    rows = []
    for password in passwords:
        level = evaluate_password(
            password, counts, CRITERIA, FORBIDDEN_PASSWORDS
        )
        rows.append((password, len(password), counts[password], level))
        print(
            f"{password:<23} {len(password):<8} {counts[password]:<8} {level}"
        )
    return rows

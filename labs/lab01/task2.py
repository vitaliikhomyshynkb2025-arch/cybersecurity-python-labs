"""Перевірка доступу з пріоритетом заборони над рівнем допуску."""

from labs.lab01.variant import BLOCKED_USERS, RESOURCES, SECURITY_LEVELS, USERS


def check_access(username, resource, users=USERS, blocked=BLOCKED_USERS):
    """Перевірити існування, блокування, активність і допуск."""
    if username not in users:
        return "DENY (User not found)"
    if username in blocked:
        return "DENY (User is blocked)"
    user = users[username]
    if not user["active"]:
        return "DENY (Account inactive)"
    if user["clearance"] >= resource[1]:
        return "ALLOW"
    return "DENY (Insufficient clearance)"


def run():
    """Показати ресурси та всі 50 перевірок з вихідних даних."""
    print("\nЗавдання 2 | Ресурси")
    for name, level in RESOURCES:
        print(f"{name:<23} {SECURITY_LEVELS[level - 1]}")
    results = []
    for username in USERS:
        for resource in RESOURCES:
            result = check_access(username, resource)
            results.append((username, resource[0], result))
            print(f"user={username} resource={resource[0]} -> {result}")
    print("Додаткові перевірки гілок алгоритму:")
    print("unknown_user ->", check_access("unknown_user", RESOURCES[0]))
    inactive_users = {"inactive_demo": {"active": False, "clearance": 4}}
    print(
        "inactive_demo ->",
        check_access("inactive_demo", RESOURCES[0], inactive_users, set()),
    )
    return results

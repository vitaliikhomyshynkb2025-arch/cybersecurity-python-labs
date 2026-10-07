"""Користувачі, сеанси й аудит із наслідуванням та композицією."""

import hashlib
import hmac
import ipaddress
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
)


def require_text(value: str) -> str:
    """Відхилити порожній або нетекстовий аргумент."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Очікується непорожній текст.")
    return value


class User:
    """Зберігати профіль і приватні параметри перевірки пароля."""

    def __init__(self, username, email, role="user", active=True):
        """Створити профіль без відкритого пароля."""
        if not isinstance(active, bool):
            raise TypeError("active має бути bool.")
        self.username = require_text(username)
        self.role = require_text(role)
        self.active = active
        self.email = email
        self.__password_hash = None
        self.__password_salt = None

    @property
    def email(self) -> str:
        """Повернути перевірену адресу електронної пошти."""
        return self._email

    @email.setter
    def email(self, value: str):
        """Прийняти адресу лише у форматі, заданому методичкою."""
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Некоректний формат email.")
        self._email = value

    def set_password(self, password: str):
        """Обчислити PBKDF2 з новою випадковою сіллю."""
        require_text(password)
        salt = os.urandom(SALT_BYTES)
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        self.__password_salt = salt
        self.__password_hash = derived

    def check_password(self, password: str) -> bool:
        """Порівняти похідні ключі без показу пароля чи хешу."""
        if self.__password_hash is None or not isinstance(password, str):
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self):
        """Деактивувати профіль."""
        self.active = False

    def __str__(self):
        """Показати публічні поля профілю."""
        return (
            f"User({self.username}, {self.email}, "
            f"role={self.role}, active={self.active})"
        )


class Admin(User):
    """Розширити користувача множиною дозволів."""

    def __init__(self, username, email, permissions=None):
        """Ініціалізувати базовий клас і власну колекцію прав."""
        super().__init__(username, email, role="admin")
        self.permissions = set()
        for permission in permissions or ():
            self.grant_permission(permission)

    def grant_permission(self, permission: str):
        """Додати дозвіл без повторів."""
        self.permissions.add(require_text(permission))

    def revoke_permission(self, permission: str):
        """Забрати дозвіл, якщо він існує."""
        self.permissions.discard(require_text(permission))

    def has_permission(self, permission: str) -> bool:
        """Перевірити належність дозволу множині."""
        return permission in self.permissions

    def __str__(self):
        """Показати профіль адміністратора та впорядковані права."""
        return f"{super().__str__()}, permissions={sorted(self.permissions)}"


@dataclass
class Session:
    """Зберігати IP і часові мітки сеансу в UTC."""

    ip: str
    login_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_activity: datetime = field(init=False)

    def __post_init__(self):
        """Перевірити IP та часовий пояс початку сеансу."""
        self.ip = str(ipaddress.ip_address(self.ip))
        if self.login_time.utcoffset() != timedelta(0):
            raise ValueError("Час сеансу має бути в UTC із часовим поясом.")
        self.last_activity = self.login_time

    def touch(self):
        """Зафіксувати справжню активність поточним часом UTC."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевірити таймаут без подовження сеансу."""
        if type(timeout_sec) is not int or timeout_sec <= 0:
            raise ValueError("Таймаут має бути додатним цілим числом.")
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return timedelta(0) <= elapsed < timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditEntry:
    """Описати незмінний запис аудиту трьома іменованими полями."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Накопичувати події без паролів, хешів і солей."""

    def __init__(self):
        """Створити окремий список для цього журналу."""
        self.records: list[AuditEntry] = []

    def add_log(self, username, action):
        """Додати подію з поточним часом UTC."""
        self.records.append(
            AuditEntry(
                datetime.now(timezone.utc),
                require_text(username),
                require_text(action),
            )
        )

    def show_all(self):
        """Вивести всі події у хронологічному порядку додавання."""
        for entry in self.records:
            print(
                f"{entry.timestamp.isoformat(timespec='seconds')} | "
                f"{entry.username} | {entry.action}"
            )


class UserAccount:
    """Поєднати користувача, журнал та необов'язковий сеанс."""

    def __init__(self, user: User, audit_log=None):
        """Прийняти компоненти через перевірений інтерфейс ключів."""
        self.session = None
        self["user"] = user
        self["audit_log"] = AuditLog() if audit_log is None else audit_log

    def login(self, username, password, ip) -> bool:
        """Створити сеанс лише після успішної перевірки профілю."""
        self.session = None
        success = (
            self.user.active
            and username == self.user.username
            and self.user.check_password(password)
        )
        if success:
            self.session = Session(ip)
            self.session.touch()
        action = "login_success" if success else "login_failure"
        self.audit_log.add_log(self.user.username, action)
        return success

    def is_authenticated(self) -> bool:
        """Перевірити активність профілю та чинність сеансу."""
        return bool(
            self.user.active
            and self.session
            and self.session.is_active(SESSION_TIMEOUT_SEC)
        )

    def logout(self):
        """Прибрати сеанс і додати подію виходу."""
        self.session = None
        self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key):
        """Дозволити читання трьох компонентів за ключем."""
        if key not in {"user", "session", "audit_log"}:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key, value):
        """Перевірити ключ і тип компонента перед присвоєнням."""
        allowed = {"user": User, "session": Session, "audit_log": AuditLog}
        if key not in allowed:
            raise KeyError(key)
        if not (key == "session" and value is None):
            if not isinstance(value, allowed[key]):
                raise TypeError(f"{key}: очікується {allowed[key].__name__}.")
        setattr(self, key, value)
        if key == "user":
            self.session = None


def demonstrate_email(user):
    """Показати коректну зміну та відхилення некоректного email."""
    user.email = "vitalii_23@example.org"
    print(f"Новий email: {user.email}")
    try:
        user.email = "23bad@example.org"
    except ValueError as error:
        print(f"Некоректний email відхилено: {error}")
    print(f"Email після відмови: {user.email}")


def run_demo():
    """Продемонструвати ООП та всі потрібні сценарії без очікування."""
    user = User("student08", "vitalii@example.org")
    user.set_password("Study@Python02")
    account = UserAccount(user)
    print(f"=== Модель користувача ===\n{user}")
    print(f"Невдалий вхід: {account.login('student08', 'wrong', '10.0.0.8')}")
    print(f"Сеанс після відмови: {account['session']}")
    print(
        "Успішний вхід: "
        f"{account.login('student08', 'Study@Python02', '10.0.0.8')}"
    )
    print(f"Автентифіковано: {account.is_authenticated()}")
    demonstrate_email(user)
    admin = Admin("admin08", "admin@example.org", ["read_audit"])
    admin.grant_permission("manage_users")
    admin.grant_permission("manage_users")
    print(f"=== Адміністратор ===\n{admin}")
    admin.revoke_permission("manage_users")
    print(f"Право після відкликання: {admin.has_permission('manage_users')}")
    print(f"Читання через ключ user: {account['user'].username}")
    account["audit_log"] = account.audit_log
    print("Журнал присвоєно через __setitem__ із перевіркою типу.")
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC)
    print("Таймаут змодельовано зсувом останньої активності на 900 с.")
    print(f"Після таймауту: {account.is_authenticated()}")
    account.logout()
    print(f"Після logout: {account.is_authenticated()}")
    user.deactivate()
    print(
        "Вхід деактивованого користувача: "
        f"{account.login('student08', 'Study@Python02', '10.0.0.8')}"
    )
    print("=== AuditLog UTC ===")
    account.audit_log.show_all()

"""Аналіз навчального CSV-журналу DNS для варіанта 8."""

import csv
import ipaddress
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

LOGGER = logging.getLogger("lab02")
INPUT_FIELDS = ("Timestamp", "ClientIP", "Domain", "QueryType")
OUTPUT_FIELDS = (*INPUT_FIELDS, "Reasons")
DOMAIN_PATTERN = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")
RISKY_TLD_PATTERN = re.compile(r"\.(?:top|zip|xyz)$", re.IGNORECASE)
DEFAULT_MIN_DOMAIN_LEN = 30


@dataclass(frozen=True)
class DNSQuery:
    """Зберігати нормалізовану DNS-транзакцію."""

    timestamp: datetime
    client_ip: str
    domain: str
    query_type: str


@dataclass(frozen=True)
class DNSAlert:
    """Об'єднати запит і всі причини його позначення."""

    query: DNSQuery
    reasons: tuple[str, ...]


@dataclass
class AnalysisResult:
    """Накопичувати статистику й лише підозрілі записи."""

    total: int = 0
    skipped: int = 0
    query_types: Counter = field(default_factory=Counter)
    reasons: Counter = field(default_factory=Counter)
    alerts: list[DNSAlert] = field(default_factory=list)


def normalize_domain(value: str) -> str:
    """Уніфікувати регістр і кінцеву крапку; перевірити символи."""
    domain = value.strip().lower().removesuffix(".")
    if not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("Некоректний формат домену.")
    # Довгі мітки залишаємо для виявлення аномалій у навчальному CSV.
    return domain


def read_blacklist(path: Path) -> set[str]:
    """Прочитати локальний чорний список без повторів і коментарів."""
    domains = set()
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            text = line.partition("#")[0].strip()
            if text:
                try:
                    domains.add(normalize_domain(text))
                except ValueError as error:
                    raise ValueError(
                        f"Чорний список: некоректний рядок {line_number}."
                    ) from error
    return domains


def parse_query(row: dict) -> DNSQuery:
    """Перевірити кількість полів, час, IP, домен і тип запиту."""
    if None in row or any(row.get(key) is None for key in INPUT_FIELDS):
        raise ValueError("Неправильна кількість полів CSV.")
    query_type = row["QueryType"].strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9]{0,15}", query_type):
        raise ValueError("Некоректний тип DNS-запиту.")
    timestamp = datetime.fromisoformat(row["Timestamp"].strip())
    return DNSQuery(
        timestamp,
        str(ipaddress.ip_address(row["ClientIP"].strip())),
        normalize_domain(row["Domain"]),
        query_type,
    )


def detect_reasons(query, blacklist, long_label_pattern) -> tuple[str, ...]:
    """Знайти незалежні ознаки ризику без повторення самого запису."""
    reasons = []
    labels = query.domain.split(".")
    if any(
        ".".join(labels[index:]) in blacklist for index in range(len(labels))
    ):
        reasons.append("BLACKLIST")
    if long_label_pattern.search(query.domain):
        reasons.append("LONG_LABEL")
    if RISKY_TLD_PATTERN.search(query.domain):
        reasons.append("SUSPICIOUS_TLD")
    if any(len(label) > 63 for label in labels) or len(query.domain) > 253:
        reasons.append("DNS_LENGTH_LIMIT")
    return tuple(reasons)


def analyze(dns_log: Path, blacklist_path: Path, min_domain_len: int):
    """Читати CSV послідовно та підрахувати ознаки аномалій."""
    if type(min_domain_len) is not int or min_domain_len <= 0:
        raise ValueError("Поріг довжини має бути додатним цілим числом.")
    blacklist = read_blacklist(blacklist_path)
    long_label = re.compile(rf"(?:^|\.)[^.]{{{min_domain_len},}}(?=\.)")
    result = AnalysisResult()
    LOGGER.info("Читання DNS-журналу: %s", dns_log)
    with dns_log.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or sorted(reader.fieldnames) != sorted(
            INPUT_FIELDS
        ):
            raise ValueError(
                "Очікуються заголовки: " + ", ".join(INPUT_FIELDS)
            )
        for row in reader:
            try:
                query = parse_query(row)
            except ValueError as error:
                result.skipped += 1
                LOGGER.warning(
                    "Рядок %s пропущено: %s", reader.line_num, error
                )
                continue
            result.total += 1
            result.query_types[query.query_type] += 1
            reasons = detect_reasons(query, blacklist, long_label)
            if reasons:
                result.alerts.append(DNSAlert(query, reasons))
                result.reasons.update(reasons)
                LOGGER.warning(
                    "%s | %s | %s",
                    query.client_ip,
                    query.domain,
                    ";".join(reasons),
                )
    if not result.total:
        raise ValueError("Журнал не містить жодного коректного DNS-запиту.")
    LOGGER.info("Оброблено: %s; пропущено: %s.", result.total, result.skipped)
    return result


def validate_output(output: Path, inputs):
    """Заборонити перезапис джерел, їхніх символьних і жорстких посилань."""
    for source in inputs:
        if output.resolve() == source.resolve() or (
            output.exists() and source.exists() and output.samefile(source)
        ):
            raise ValueError("Вихідний CSV не може замінювати вхідний файл.")


def write_alerts(output: Path, alerts: list[DNSAlert]):
    """Зберегти один рядок на запит, атомарно замінивши результат."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=output.parent,
            prefix=".dns-alerts-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            writer = csv.writer(stream)
            writer.writerow(OUTPUT_FIELDS)
            for alert in alerts:
                query = alert.query
                writer.writerow(
                    (
                        query.timestamp.isoformat(),
                        query.client_ip,
                        query.domain,
                        query.query_type,
                        ";".join(alert.reasons),
                    )
                )
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def show_summary(result: AnalysisResult):
    """Показати частки типів запитів і пояснити всі позначені записи."""
    print("=== Статистика DNS-запитів ===")
    for query_type, count in sorted(result.query_types.items()):
        print(f"{query_type:<5}: {count:>2} ({count / result.total:.1%})")
    print(f"Підозрілі запити: {len(result.alerts)} із {result.total}")
    print("=== Причини позначення ===")
    for alert in result.alerts:
        print(f"{alert.query.domain} | {', '.join(alert.reasons)}")
    print("Ознаки ризику потребують перевірки; це не доказ атаки.")


def run_analysis(dns_log, blacklist, out_csv, min_domain_len):
    """Перевірити шляхи, проаналізувати дані й зберегти CSV."""
    validate_output(out_csv, (dns_log, blacklist))
    result = analyze(dns_log, blacklist, min_domain_len)
    write_alerts(out_csv, result.alerts)
    show_summary(result)
    LOGGER.info(
        "CSV із %s записами збережено: %s", len(result.alerts), out_csv
    )
    return result

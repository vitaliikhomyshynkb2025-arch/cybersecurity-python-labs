"""Команди demo та analyze лабораторної 2 за варіантом 8."""

import argparse
import csv
import logging
import sys
from pathlib import Path

from labs.lab02 import task1, task2
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

DATA_DIR = Path(__file__).resolve().parent / "data" / "data_v08"


def positive_integer(value: str) -> int:
    """Перевірити додатне ціле число на рівні argparse."""
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Очікується ціле число.") from error
    if number <= 0:
        raise argparse.ArgumentTypeError("Число має бути більше нуля.")
    return number


def build_parser():
    """Описати дві підкоманди та параметри DNS-аналізатора."""
    parser = argparse.ArgumentParser(description="ЛР2: ООП та DNS, варіант 8")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="Показати користувачів, сесії та аудит")
    analyze = commands.add_parser("analyze", help="Проаналізувати DNS CSV")
    analyze.add_argument(
        "--dns-log", type=Path, default=DATA_DIR / "dns_queries.csv"
    )
    analyze.add_argument(
        "--blacklist", type=Path, default=DATA_DIR / "blacklist.txt"
    )
    analyze.add_argument(
        "--out-csv", type=Path, default=DATA_DIR / "dns_alerts.csv"
    )
    analyze.add_argument(
        "--min-domain-len",
        type=positive_integer,
        default=task2.DEFAULT_MIN_DOMAIN_LEN,
        help="Мінімальна довжина DNS-мітки для LONG_LABEL (типово 30)",
    )
    return parser


def configure_logging():
    """Виводити структуровані повідомлення у термінал."""
    logger = task2.LOGGER
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def execute(args):
    """Виконати команду або коротко повідомити про очікувану помилку."""
    try:
        if args.command == "demo":
            task1.run_demo()
        else:
            task2.run_analysis(
                args.dns_log, args.blacklist, args.out_csv, args.min_domain_len
            )
    except (OSError, ValueError, csv.Error) as error:
        task2.LOGGER.error("%s: %s", type(error).__name__, error)
        return 1
    return 0


def main(argv=None):
    """Прочитати аргументи та повернути код завершення CLI."""
    args = build_parser().parse_args(argv)
    configure_logging()
    if VARIANT_NUMBER != 8:
        task2.LOGGER.error("Ця утиліта реалізує лише варіант 8.")
        return 1
    print(f"{STUDENT_NAME} | {GROUP_NAME} | Варіант {VARIANT_NUMBER}")
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())

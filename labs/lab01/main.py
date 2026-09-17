"""Запуск трьох завдань лабораторної роботи як пакета."""

import argparse

from labs.lab01 import task1, task2, task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    """Прочитати параметр відтворюваності й виконати лабораторну."""
    parser = argparse.ArgumentParser(description="ЛР1, варіант 8")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    print(f"{STUDENT_NAME} | {GROUP_NAME} | Варіант {VARIANT_NUMBER}")
    task1.run(args.seed)
    task2.run()
    return 0 if task3.run() else 1


if __name__ == "__main__":
    raise SystemExit(main())

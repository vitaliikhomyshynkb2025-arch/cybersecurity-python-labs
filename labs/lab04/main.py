"""CLI аналізу NVD з окремими stdout, stderr та кодами завершення."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER


def load_response(path: str | Path) -> Any:
    """Прочитати UTF-8 JSON локально, не викликаючи HTTP-клієнт."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cve_argument(value: str) -> str:
    """Перетворити перевірку CVE на зрозумілу помилку argparse."""
    try:
        return analysis.validate_cve_id(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def _execute(args: argparse.Namespace, variant: int) -> int:
    """Виконати обраний режим і безпечно повідомити очікувані помилки."""
    try:
        payload = (
            load_response(args.input)
            if args.input is not None
            else api_client.fetch_response(args.cve)
        )
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, variant)
    except api_client.APIClientError as error:
        print(str(error), file=sys.stderr)
        return 1
    except FileNotFoundError:
        print("Файл локальної відповіді не знайдено.", file=sys.stderr)
        return 1
    except PermissionError:
        print("Немає дозволу на читання локального файла.", file=sys.stderr)
        return 1
    except UnicodeError:
        print("Локальний файл має бути у кодуванні UTF-8.", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("Локальний файл не є коректним JSON.", file=sys.stderr)
        return 1
    except OSError:
        print("Не вдалося прочитати локальний файл.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Помилка структури даних: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Перевірити варіант і аргументи та передати роботу виконавцю."""
    parser = argparse.ArgumentParser(
        description="Навчальний аналіз CVE через NVD або локальний JSON"
    )
    try:
        variant = analysis.validate_variant(VARIANT_NUMBER)
    except ValueError as error:
        parser.error(str(error))
    parser.add_argument("--cve", required=True, type=_cve_argument)
    parser.add_argument("--input", type=Path, help="локальна відповідь NVD")
    return _execute(parser.parse_args(argv), variant)


if __name__ == "__main__":
    raise SystemExit(main())

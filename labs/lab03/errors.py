"""Перетворення очікуваних помилок на безпечні HTTP-відповіді."""

import logging
import sqlite3

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from labs.lab03.repository import MissingResource

LOGGER = logging.getLogger(__name__)


def not_found(request: Request, error: MissingResource) -> JSONResponse:
    """Повернути 404 для відсутнього ресурсу."""
    return JSONResponse(status_code=404, content={"detail": str(error)})


def conflict(request: Request, error: sqlite3.IntegrityError) -> JSONResponse:
    """Повернути 409 без SQL і внутрішніх назв обмежень."""
    return JSONResponse(
        status_code=409,
        content={"detail": "Конфлікт унікальності або зв'язків даних."},
    )


def database_error(request: Request, error: sqlite3.Error) -> JSONResponse:
    """Записати технічну причину в журнал, а клієнту повернути 500."""
    LOGGER.error(
        "Помилка SQLite", exc_info=(type(error), error, error.__traceback__)
    )
    return JSONResponse(
        status_code=500, content={"detail": "Помилка роботи з базою даних."}
    )


def invalid_input(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    """Повернути 422, не копіюючи NaN або секретні вхідні дані у JSON."""
    details = [
        {key: item[key] for key in ("loc", "msg", "type")}
        for item in error.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": details})


def register_handlers(app: FastAPI) -> None:
    """Зареєструвати спільні обробники й залишити маршрути простими."""
    app.add_exception_handler(MissingResource, not_found)
    app.add_exception_handler(sqlite3.IntegrityError, conflict)
    app.add_exception_handler(sqlite3.Error, database_error)
    app.add_exception_handler(RequestValidationError, invalid_input)

"""FastAPI-застосунок обліку часу відновлення сервісів, варіант 8."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03 import database
from labs.lab03.config import SUBJECT, THRESHOLD, UNIT
from labs.lab03.errors import register_handlers
from labs.lab03.routers import categories, records
from labs.lab03.schemas import PingRead, StudentRead
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці один раз під час запуску API."""
    database.initialize_database()
    yield


app = FastAPI(
    title=SUBJECT,
    description=(
        f"Навчальні вимірювання відновлення database, web_service і "
        f"file_storage. Одиниця value — {UNIT} (хвилини), поріг — "
        f"{THRESHOLD:g}. Поріг використовується для фільтрації, а не як "
        "верхня межа допустимого часу. Варіант 8."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
register_handlers(app)
app.include_router(categories.router)
app.include_router(records.router)


@app.get(
    "/ping", response_model=PingRead, tags=["Сервіс"], summary="Перевірка API"
)
def ping() -> dict:
    """Підтвердити доступність застосунку."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentRead,
    tags=["Сервіс"],
    summary="Дані студента",
)
def student() -> dict:
    """Прочитати дані зі спільного модуля попередніх лабораторних."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }

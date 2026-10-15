"""CRUD вимірювань, буквальний пошук, фільтри та атомарні пакети."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, Response

from labs.lab03 import repository
from labs.lab03.config import VALUE_MAX
from labs.lab03.schemas import (
    ErrorMessage,
    RecordCreate,
    RecordRead,
    RecordReplace,
    Status,
)

router = APIRouter(prefix="/records", tags=["Вимірювання"])
RecordId = Annotated[int, Path(gt=0, description="Додатний id вимірювання")]
ERRORS = {
    404: {
        "model": ErrorMessage,
        "description": "Запис або категорія відсутні",
    },
    409: {"model": ErrorMessage, "description": "Код запису вже існує"},
}


@router.get("", response_model=list[RecordRead], summary="Список вимірювань")
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Категорія сервісу")
    ] = None,
    status: Annotated[
        Status | None, Query(description="Стан перевірки вимірювання")
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=0,
            le=VALUE_MAX,
            allow_inf_nan=False,
            description="Мінімальний час у хвилинах, включно з рівністю",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Буквальний підрядок у title з урахуванням регістру",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=100,
            description="Розмір сторінки",
        ),
    ] = 20,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="Кількість пропущених записів",
        ),
    ] = 0,
) -> list[dict]:
    """Поєднати фільтри через AND; q враховує регістр та буквальні % і _."""
    return repository.list_records(
        category_id, status, min_value, q, limit, offset
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    responses=ERRORS,
    summary="Додати пакет із 1–100 вимірювань",
)
def create_bulk(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    """Скасувати весь пакет, якщо будь-який елемент не вдалося додати."""
    return repository.create_records(
        [record.model_dump() for record in records]
    )


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    responses=ERRORS,
    summary="Створити вимірювання",
)
def create_record(record: RecordCreate) -> dict:
    """Створити запис без клієнтського id та повернути назву категорії."""
    return repository.create_records([record.model_dump()])[0]


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    responses={404: ERRORS[404]},
    summary="Прочитати вимірювання",
)
def get_record(record_id: RecordId) -> dict:
    """Отримати один запис за додатним id."""
    return repository.get_record(record_id)


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    responses=ERRORS,
    summary="Повністю замінити вимірювання",
)
def replace_record(record_id: RecordId, record: RecordReplace) -> dict:
    """Оновити всі п'ять змінюваних полів зі збереженням id."""
    return repository.replace_record(record_id, record.model_dump())


@router.delete(
    "/{record_id}",
    status_code=204,
    responses={404: ERRORS[404]},
    summary="Видалити вимірювання",
)
def delete_record(record_id: RecordId) -> Response:
    """Видалити запис та повернути порожнє тіло відповіді."""
    repository.delete_record(record_id)
    return Response(status_code=204)

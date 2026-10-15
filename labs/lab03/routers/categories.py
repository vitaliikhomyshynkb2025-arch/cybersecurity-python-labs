"""Маршрути створення, читання та видалення категорій сервісів."""

from typing import Annotated

from fastapi import APIRouter, Path, Response

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead, ErrorMessage

router = APIRouter(prefix="/categories", tags=["Категорії"])
ERRORS = {
    404: {"model": ErrorMessage, "description": "Категорія відсутня"},
    409: {"model": ErrorMessage, "description": "Конфлікт назви або зв'язків"},
}


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories() -> list[dict]:
    """Отримати категорії за зростанням id."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    responses={409: ERRORS[409]},
    summary="Створити категорію",
)
def create_category(category: CategoryCreate) -> dict:
    """Додати назву; id створює база, повторна назва дає 409."""
    return repository.create_category(category.name)


@router.delete(
    "/{category_id}",
    status_code=204,
    responses=ERRORS,
    summary="Видалити порожню категорію",
)
def delete_category(
    category_id: Annotated[
        int, Path(gt=0, description="Додатний id категорії")
    ],
) -> Response:
    """Відхилити видалення категорії з вимірюваннями кодом 409."""
    repository.delete_category(category_id)
    return Response(status_code=204)

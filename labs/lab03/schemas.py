"""Моделі запитів, відповідей і початкових даних варіанта 8."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MAX

Status = Literal["new", "in_progress", "done"]
PositiveId = Annotated[int, Field(gt=0, strict=True)]


class InputModel(BaseModel):
    """Обрізати пробіли та відхиляти невідомі поля."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")


class CategoryCreate(InputModel):
    """Прийняти назву категорії без клієнтського id."""

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Повернути категорію з ідентифікатором бази."""

    id: PositiveId


class RecordCreate(InputModel):
    """Перевірити всі змінювані поля вимірювання у хвилинах."""

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: PositiveId
    value: float = Field(ge=0, le=VALUE_MAX, allow_inf_nan=False, strict=True)
    status: Status


class RecordReplace(RecordCreate):
    """Вимагати всі п'ять полів для повного оновлення PUT."""


class RecordRead(RecordCreate):
    """Повернути вимірювання разом із назвою категорії через JOIN."""

    id: PositiveId
    category_name: str


class SeedData(InputModel):
    """Перевірити три категорії з id та вісім навчальних записів."""

    categories: list[CategoryRead] = Field(min_length=3, max_length=3)
    records: list[RecordCreate] = Field(min_length=8, max_length=8)


class ErrorMessage(BaseModel):
    """Описати зрозумілу помилку без технічних подробиць."""

    detail: str


class StudentRead(BaseModel):
    """Повернути підтверджені дані студента зі спільного модуля."""

    student_name: str
    group_name: str
    variant_number: int


class PingRead(BaseModel):
    """Підтвердити доступність API."""

    status: Literal["ok"]

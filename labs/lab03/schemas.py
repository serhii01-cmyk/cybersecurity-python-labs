"""Pydantic-моделі запитів та відповідей Web API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CategoryCreate(BaseModel):
    """Модель створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Модель читання категорії."""

    id: int = Field(gt=0)


class RecordCreate(BaseModel):
    """Модель створення запису (Варіант 6: value - int >= 0)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: int = Field(ge=0)
    status: Literal["new", "in_progress", "done"]


class RecordReplace(RecordCreate):
    """Модель для PUT оновлення запису."""


class RecordRead(RecordCreate):
    """Модель повернення запису клієнту."""

    id: int = Field(gt=0)
    category_name: str

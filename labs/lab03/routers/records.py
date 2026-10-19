"""Маршрути для управління записами спостережень."""

import sqlite3
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, status

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[RecordRead])
def read_records(
    category_id: int | None = Query(None, gt=0),
    status_filter: Literal["new", "in_progress", "done"] | None = Query(
        None, alias="status"
    ),
    min_value: int | None = Query(None, ge=0),
    q: str | None = Query(None, min_length=1, max_length=120),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Отримати список записів із фільтрацією та пагінацією."""
    return repository.get_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/{record_id}", response_model=RecordRead)
def read_record(record_id: int):
    """Отримати один запис за id."""
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ID має бути додатним",
        )
    record = repository.get_record_by_id(record_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис не знайдено",
        )
    return record


@router.post("", response_model=RecordRead, status_code=status.HTTP_201_CREATED)
def create_record(record: RecordCreate):
    """Створити один запис."""
    if not repository.get_category_by_id(record.category_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Вказана категорія не існує",
        )
    try:
        return repository.create_record(
            code=record.code,
            title=record.title,
            category_id=record.category_id,
            value=record.value,
            status=record.status,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Запис із таким кодом вже існує",
        )


@router.put("/{record_id}", response_model=RecordRead)
def update_record(record_id: int, record: RecordReplace):
    """Повна заміна змінюваних полів запису."""
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ID має бути додатним",
        )
    if not repository.get_record_by_id(record_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис для оновлення не знайдено",
        )
    if not repository.get_category_by_id(record.category_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Вказана категорія не існує",
        )
    try:
        updated = repository.update_record(
            record_id=record_id,
            code=record.code,
            title=record.title,
            category_id=record.category_id,
            value=record.value,
            status=record.status,
        )
        return updated
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Запис із таким кодом вже існує",
        )


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int):
    """Видалити запис."""
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ID має бути додатним",
        )
    if not repository.delete_record(record_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис не знайдено",
        )


@router.post(
    "/bulk", response_model=list[RecordRead], status_code=status.HTTP_201_CREATED
)
def create_records_bulk(records: list[RecordCreate]):
    """Пакетне створення записів з атомарним збереженням."""
    if len(records) < 1 or len(records) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Розмір пакета має бути від 1 до 100 елементів",
        )

    codes = [r.code for r in records]
    if len(codes) != len(set(codes)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="У пакеті присутні дублікати коду",
        )

    for r in records:
        if not repository.get_category_by_id(r.category_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Категорію з id={r.category_id} не знайдено",
            )

    try:
        records_data = [r.model_dump() for r in records]
        return repository.create_records_bulk(records_data)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Один із кодів записів вже існує в базі даних",
        )

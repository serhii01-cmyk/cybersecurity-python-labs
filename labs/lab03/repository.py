"""Шар доступу до даних (Repository) з параметризованими SQL-запитами."""

from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection

# --- Категорії ---


def get_categories() -> list[dict[str, Any]]:
    """Отримати список категорій за зростанням id."""
    with closing(get_connection()) as conn:
        cursor = conn.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]


def get_category_by_id(category_id: int) -> dict[str, Any] | None:
    """Отримати категорію за id."""
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "SELECT id, name FROM categories WHERE id = ?", (category_id,)
        )
        row = cursor.fetchone()
        return {"id": row[0], "name": row[1]} if row else None


def get_category_by_name(name: str) -> dict[str, Any] | None:
    """Отримати категорію за назвою."""
    with closing(get_connection()) as conn:
        cursor = conn.execute("SELECT id, name FROM categories WHERE name = ?", (name,))
        row = cursor.fetchone()
        return {"id": row[0], "name": row[1]} if row else None


def create_category(name: str) -> dict[str, Any]:
    """Створити нову категорію."""
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("INSERT INTO categories (name) VALUES (?)", (name,))
        cat_id = cursor.lastrowid
    return {"id": cat_id, "name": name}


def delete_category(category_id: int) -> bool:
    """Видалити порожню категорію."""
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        return cursor.rowcount > 0


# --- Записи ---


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: int | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Отримати список записів з фільтрацією та пагінацією."""
    query = """
        SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE 1=1
    """
    params: list[Any] = []

    if category_id is not None:
        query += " AND r.category_id = ?"
        params.append(category_id)
    if status is not None:
        query += " AND r.status = ?"
        params.append(status)
    if min_value is not None:
        query += " AND r.value >= ?"
        params.append(min_value)
    if q is not None and q.strip():
        query += " AND INSTR(r.title, ?) > 0"
        params.append(q)

    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as conn:
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "code": r[1],
                "title": r[2],
                "category_id": r[3],
                "category_name": r[4],
                "value": r[5],
                "status": r[6],
            }
            for r in rows
        ]


def get_record_by_id(record_id: int) -> dict[str, Any] | None:
    """Отримати один запис за id."""
    query = """
        SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE r.id = ?
    """
    with closing(get_connection()) as conn:
        cursor = conn.execute(query, (record_id,))
        r = cursor.fetchone()
        if not r:
            return None
        return {
            "id": r[0],
            "code": r[1],
            "title": r[2],
            "category_id": r[3],
            "category_name": r[4],
            "value": r[5],
            "status": r[6],
        }


def create_record(
    code: str, title: str, category_id: int, value: int, status: str
) -> dict[str, Any]:
    """Створити один запис."""
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute(
            "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
            (code, title, category_id, value, status),
        )
        rec_id = cursor.lastrowid

    return get_record_by_id(rec_id)  # type: ignore


def update_record(
    record_id: int, code: str, title: str, category_id: int, value: int, status: str
) -> dict[str, Any] | None:
    """Повною мірою оновити змінювані поля запису."""
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute(
            "UPDATE records SET code = ?, title = ?, category_id = ?, value = ?, status = ? WHERE id = ?",
            (code, title, category_id, value, status, record_id),
        )
        if cursor.rowcount == 0:
            return None

    return get_record_by_id(record_id)


def delete_record(record_id: int) -> bool:
    """Видалити запис."""
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        return cursor.rowcount > 0


def create_records_bulk(records_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Пакетне атомарне створення записів у межах єдиної транзакції."""
    created_ids = []
    with closing(get_connection()) as conn, conn:  # Атомарна транзакція
        for r in records_data:
            cursor = conn.execute(
                "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                (r["code"], r["title"], r["category_id"], r["value"], r["status"]),
            )
            created_ids.append(cursor.lastrowid)

    return [get_record_by_id(rid) for rid in created_ids]  # type: ignore

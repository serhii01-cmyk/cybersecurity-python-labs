"""Скрипт початкового заповнення бази даних з seed.json."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database

BASE_DIR = Path(__file__).resolve().parent
SEED_PATH = BASE_DIR / "data" / "seed.json"


def seed_database() -> None:
    """Заповнити порожню базу даними із seed.json у межах однієї транзакції."""
    initialize_database()

    with closing(get_connection()) as conn:
        cat_count = conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        rec_count = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]

        if cat_count > 0 or rec_count > 0:
            print("База даних вже містить дані. Заповнення скасовано.")
            return

        if not SEED_PATH.exists():
            print(f"Файл початкових даних {SEED_PATH} не знайдено.")
            return

        with open(SEED_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        try:
            with conn:
                for cat in data.get("categories", []):
                    conn.execute(
                        "INSERT INTO categories (id, name) VALUES (?, ?)",
                        (cat["id"], cat["name"]),
                    )
                for rec in data.get("records", []):
                    conn.execute(
                        "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                        (
                            rec["code"],
                            rec["title"],
                            rec["category_id"],
                            rec["value"],
                            rec["status"],
                        ),
                    )
            print("Базу даних успішно заповнено початковими даними!")
        except sqlite3.Error as e:
            print(f"Помилка заповнення бази даних: {e}. Зміни скасовано.")


if __name__ == "__main__":
    seed_database()

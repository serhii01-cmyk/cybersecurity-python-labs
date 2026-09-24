"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування (Варіант 6)."""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_PATH = os.path.join(DATA_DIR, "log.json")

HASH_ALGORITHM = "blake2s"
MIN_PASSWORD_LEN = 9
PERSONAL_SALT = f"{VARIANT_NUMBER:0>5}"  


class ValidationError(Exception):
    """Власний виняток для помилок валідації пароля."""


def log_event(func):
    """Декоратор для логування спроб входу у файл JSON."""

    @functools.wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            result_bool = func(username, password, *args, **kwargs)
            result_str = "success" if result_bool else "failure"
        except Exception as e:
            result_str = f"failure ({type(e).__name__})"
            write_log(
                event="login",
                user=username,
                result=result_str,
                timestamp=timestamp,
                args=list(args),
                kwargs=kwargs,
            )
            raise

        write_log(
            event="login",
            user=username,
            result=result_str,
            timestamp=timestamp,
            args=list(args),
            kwargs=kwargs,
        )
        return result_bool

    return wrapper


def write_log(
    event: str,
    user: str,
    result: str,
    timestamp: str,
    args: list,
    kwargs: dict,
) -> None:
    """Записує подію логу у JSON-файл."""
    log_entry = {
        "event": event,
        "user": user,
        "result": result,
        "timestamp": timestamp,
        "args": args,
        "kwargs": kwargs,
    }

    os.makedirs(DATA_DIR, exist_ok=True)
    logs = []
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except (json.JSONDecodeError, OSError):
            logs = []

    logs.append(log_entry)

    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує хеш від пароля та солі за допомогою blake2s."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LEN:
        raise ValidationError(
            f"Пароль занадто короткий. Мін. довжина: {MIN_PASSWORD_LEN}"
        )

    data = (password + salt).encode("utf-8")
    return hashlib.blake2s(data).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з хешованим паролем."""
    hash_val = generate_hash(password, PERSONAL_SALT)
    return username, hash_val


def create_users(users_list: list[tuple[str, str]]) -> None:
    """Записує базу користувачів у CSV файл."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for user, pwd in users_list:
            u_name, u_hash = create_user(user, pwd)
            writer.writerow([u_name, u_hash])


def read_users_db() -> list[tuple[str, str]]:
    """Зчитує вміст CSV-файлу."""
    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(f"Файл {CSV_PATH} не знайдено.")

    users_db = []
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                users_db.append((row[0], row[1]))
    return users_db


@log_event
def login(username: str, password: str) -> bool:
    """Виконує аутентифікацію користувача."""
    if not username or not password:
        raise ValueError("Логін та пароль є обов'язковими")

    users_db = read_users_db()
    input_hash = generate_hash(password, PERSONAL_SALT)

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == input_hash:
            return True
    return False


def main() -> None:
    """Головна функція виконання Завдання 3."""
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    users_to_register = (
        ("admin_sec", "SecurePass123!"),
        ("analyst_01", "Complex#Pass99"),
        ("operator_a", "OpPassword2023!"),
        ("auditor_x", "AuditKey#888"),
        ("dev_lead", "DevPassWord@1"),
        ("tester_02", "TestRigorously#7"),
        ("guest_user", "Guest@2023Pass"),
        ("sys_admin", "RootAccess!2023"),
        ("db_admin", "DBPassword#999"),
        ("sec_officer", "OfficerPass!12"),
    )

    try:
        create_users(users_to_register)
        print(f"Базу даних створено в: {CSV_PATH}")

        users_db = read_users_db()
        print("\n--- База користувачів (users.csv) ---")
        print(f"{'Логін':<20} | {'Хеш (blake2s)':<40}")
        print("-" * 65)
        for user, pwd_hash in users_db:
            print(f"{user:<20} | {pwd_hash:<40}")

        print("\n--- Перевірка аутентифікації ---")
        test_logins = [
            ("admin_sec", "SecurePass123!"),
            ("admin_sec", "WrongPass123!"),
            ("unknown_user", "SomePass123!"),
        ]

        for u, p in test_logins:
            res = login(u, p)
            status = "УСПІШНО" if res else "ВІДМОВЛЕНО"
            print(f"Вхід для [{u}]: {status}")

    except (
        OSError,
        ValidationError,
        ValueError,
    ) as e:
        print(f"Помилка: {e}")


if __name__ == "__main__":
    main()
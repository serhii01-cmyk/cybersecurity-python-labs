
import os
import random
import sys

# Додаємо шлях до кореневої папки проекту для імпорту shared
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для Варіанта 6
PASSWORDS = [
    "InfoS3c@2023",
    "simple123",
    "Def3ns3@Key",
    "public",
    "Encrypt3d#Pass",
    "basic123",
    "Secur3@Analysis",
    "temp123",
    "Prot3ct@Data",
    "default",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "simple123",
    "public",
    "basic123",
    "temp123",
    "default",
    "guest",
}


def evaluate_password(password: str, all_passwords: list[str]) -> str:
    """Оцінює надійність пароля за заданими критеріями."""
    min_length = CRITERIA["min_length"]
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    has_special = any(char in special_chars for char in password)

    # 1. Заборонений
    if password in FORBIDDEN_PASSWORDS or len(password) < min_length:
        return "Заборонений"

    # Перевірка виконання всіх критеріїв безпеки
    meets_all_criteria = has_digit and has_upper and has_lower and has_special

    # 2. Слабкий (виконує хоча б один з критеріїв безпеки)
    meets_any_criteria = has_digit or has_upper or has_lower or has_special
    if not meets_all_criteria and meets_any_criteria:
        # Може бути "Слабкий" або "Середній"
        if (
            len(password) >= min_length
            and (has_digit + has_upper + has_lower + has_special) >= 2
        ):
            return "Середній"
        return "Слабкий"

    # Перевірка унікальності
    is_unique = all_passwords.count(password) == 1

    # 3. Дуже сильний
    if meets_all_criteria and len(password) >= min_length + 4 and is_unique:
        return "Дуже сильний"

    # 4. Сильний
    if meets_all_criteria:
        return "Сильний"

    return "Слабкий"


def main() -> None:
    """Головна функція для виконання Завдання 1."""
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    # Робимо копію списку паролів
    working_passwords = PASSWORDS.copy()

    # Генерація 3 випадкових індексів та додавання дублікатів
    random.seed(42)  # Фіксуємо seed для відтворюваності
    random_indices = [random.randint(0, len(PASSWORDS) - 1) for _ in range(3)]
    for idx in random_indices:
        working_passwords.append(PASSWORDS[idx])

    print("--- Результати аналізу паролів ---")
    print(f"{'Пароль':<20} | {'Категорія надійності':<20}")
    print("-" * 45)

    for pwd in working_passwords:
        category = evaluate_password(pwd, working_passwords)
        print(f"{pwd:<20} | {category:<20}")


if __name__ == "__main__":
    main()
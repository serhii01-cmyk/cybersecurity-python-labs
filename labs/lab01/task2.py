"""Завдання 2: Багаторівнева система контролю доступу (Варіант 6)."""

import os
import sys

# Додаємо шлях до кореневої папки проекту для імпорту shared
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для Варіанта 6
USERS = {
    "red_team_lead": {
        "role": "red_team",
        "clearance": 4,
        "department": "Red Team",
        "active": True,
    },
    "blue_team_analyst": {
        "role": "blue_team",
        "clearance": 3,
        "department": "Blue Team",
        "active": True,
    },
    "purple_team_coord": {
        "role": "purple_team",
        "clearance": 3,
        "department": "Purple Team",
        "active": True,
    },
    "student_intern": {
        "role": "student",
        "clearance": 1,
        "department": "Academia",
        "active": True,
    },
    "retired_expert": {
        "role": "retired",
        "clearance": 2,
        "department": "Emeritus",
        "active": False,
    },
}

RESOURCES = [
    ("attack_scenarios", 4),
    ("defense_playbooks", 3),
    ("exercise_plans", 3),
    ("research_papers", 1),
    ("exploit_tools", 4),
    ("student_resources", 1),
    ("simulation_results", 3),
    ("red_team_tools", 4),
    ("blue_team_reports", 3),
    ("public_research", 1),
]

SECURITY_LEVELS = ("Academic", "Operational", "Tactical", "Strategic")
BLOCKED_USERS = {"retired_expert", "academic_violator", "leaked_account"}


def check_access(username: str, resource_name: str, resource_level: int) -> tuple[str, str]:
    """Перевіряє доступ користувача до ресурсу відповідно до алгоритму."""
    if username not in USERS:
        return "DENY", "User not found"

    if username in BLOCKED_USERS:
        return "DENY", "User is blocked"

    user_info = USERS[username]

    if not user_info.get("active", False):
        return "DENY", "Account inactive"

    user_clearance = user_info.get("clearance", 0)

    if user_clearance >= resource_level:
        return "ALLOW", ""

    return "DENY", "Insufficient clearance"


def main() -> None:
    """Головна функція для виконання Завдання 2."""
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    print("--- Список ресурсів системи ---")
    for res_name, res_level in RESOURCES:
        # Індексація з 0: рівень 1 -> index 0
        level_label = SECURITY_LEVELS[res_level - 1]
        print(f"Ресурс: {res_name:<20} | Рівень безпеки: {level_label}")

    print("\n--- Перевірка прав доступу ---")
    # Перевіряємо всіх користувачів зі словника та одного відсутнього тестового
    test_users = list(USERS.keys()) + ["unknown_user"]

    for username in test_users:
        for res_name, res_level in RESOURCES:
            status, reason = check_access(username, res_name, res_level)
            reason_str = f" ({reason})" if reason else ""
            print(f"user=[{username}] resource=[{res_name}] -> {status}{reason_str}")


if __name__ == "__main__":
    main()
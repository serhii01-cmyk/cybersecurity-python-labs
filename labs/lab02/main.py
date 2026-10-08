import argparse
import logging
import sys
from pathlib import Path

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import run_password_audit


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
    )


def run_demo():
    """Демонстраційний сценарій для Завдання 1."""
    print("=== Демонстрація Завдання 1 (ООП) ===")

    # Створення об'єктів
    audit = AuditLog()
    user = User("j_doe", "john_doe@example.com")
    user.set_password("SecurePass123!")

    account = UserAccount(user, audit)

    # 1. Успішний і невдалий вхід
    print("\n1. Тестування входу:")
    print(
        "Спроба входу з невірним паролем:",
        account.login("j_doe", "WrongPass", "192.168.1.10"),
    )
    print(
        "Спроба входу з вірним паролем:",
        account.login("j_doe", "SecurePass123!", "192.168.1.10"),
    )
    print("Статус автентифікації:", account.is_authenticated())

    # 2. Перевірка email та setter з валідацією
    print("\n2. Зміна Email:")
    try:
        user.email = "bad_email"
    except ValueError as e:
        print(f"Спіймано очікувану помилку: {e}")

    user.email = "valid_user@company.com"
    print("Оновлений email:", user.email)

    # 3. Права адміністратора
    print("\n3. Тест ролі Admin:")
    admin = Admin("admin_user", "admin.main@company.com")
    admin.grant_permission("READ_LOGS")
    admin.grant_permission("DELETE_USER")
    print(admin)
    print("Чи є право DELETE_USER?:", admin.has_permission("DELETE_USER"))

    # 4. Вихід із системи та перевірка журналів
    print("\n4. Завершення сеансу та Журнал Аудиту:")
    account.logout()
    print("Статус автентифікації після logout:", account.is_authenticated())

    print("\nЗаписи AuditLog:")
    for log in audit.show_all():
        print(f"[{log.timestamp.strftime('%H:%M:%S')}] {log.username} -> {log.action}")


def main():
    parser = argparse.ArgumentParser(
        description="Лабораторна робота №2: CLI Утиліти для задач кібербезпеки"
    )
    subparsers = parser.add_subparsers(dest="command", help="Команда для виконання")

    # Команда demo
    subparsers.add_parser("demo", help="Запустити демонстрацію Завдання 1 (ООП)")

    # Команда analyze (Завдання 2)
    analyze_parser = subparsers.add_parser("analyze", help="Аналіз словника паролів")
    analyze_parser.add_argument(
        "--wordlist",
        type=Path,
        required=True,
        help="Шлях до текстового файлу словника паролів",
    )
    analyze_parser.add_argument(
        "--min-length",
        type=int,
        default=8,
        help="Мінімальна довжина безпечного пароля (дефолт: 8)",
    )
    analyze_parser.add_argument(
        "--top-masks",
        type=int,
        default=5,
        help="Кількість найпопулярніших масок у звіті (дефолт: 5)",
    )
    analyze_parser.add_argument(
        "--output-stats",
        type=Path,
        help="Шлях для збереження JSON-звіту",
    )
    analyze_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Детальний режим логування",
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        setup_logging(args.verbose)
        run_password_audit(
            wordlist_path=args.wordlist,
            output_path=args.output_stats,
            min_length=args.min_length,
            top_masks=args.top_masks,
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

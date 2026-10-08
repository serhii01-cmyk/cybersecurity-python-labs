import json
import logging
import re
from collections import Counter
from pathlib import Path

logger = logging.getLogger("PasswordAuditor")


def get_password_mask(password: str) -> str:
    """Визначає маску пароля за категоріями символів."""
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    # Визначення категорій маски
    if has_upper and has_lower and has_digit and has_special:
        return "Complex (Upper-Lower-Digit-Special)"
    elif has_upper and has_lower and has_digit:
        return "Upper-Lower-Digit (UlLd)"
    elif has_lower and has_digit:
        return "Lowercase-Digit (LdLd)"
    elif has_lower and not (has_upper or has_digit or has_special):
        return "All-Lowercase (LLLL)"
    elif has_digit and not (has_upper or has_lower or has_special):
        return "All-Digits (dddd)"
    else:
        return "Other/Mixed"


def stream_passwords(file_path: Path):
    """Генератор для читання файлу словника по одному рядку."""
    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pwd = line.strip("\r\n")
            if pwd:
                yield pwd


def analyze_wordlist(
    wordlist_path: Path, min_length: int = 8, top_masks_count: int = 5
) -> dict:
    """Аналізує словник паролів та повертає підсумкову статистику."""
    logger.info(f"Обробка файлу словника {wordlist_path} за допомогою генераторів...")

    if not wordlist_path.exists():
        logger.error(f"Файл словника не знайдено: {wordlist_path}")
        raise FileNotFoundError(f"Файл {wordlist_path} не існує.")

    total_count = 0
    weak_count = 0
    total_length = 0
    mask_counter = Counter()

    for password in stream_passwords(wordlist_path):
        total_count += 1
        length = len(password)
        total_length += length

        if length < min_length:
            weak_count += 1

        mask = get_password_mask(password)
        mask_counter[mask] += 1

    if total_count == 0:
        logger.warning("Словник порожній!")
        return {
            "total_passwords": 0,
            "weak_passwords": 0,
            "weak_percentage": 0.0,
            "avg_length": 0.0,
            "top_masks": [],
        }

    avg_length = round(total_length / total_count, 1)
    weak_percentage = round((weak_count / total_count) * 100, 1)

    top_masks = [
        {
            "mask": mask,
            "count": count,
            "percentage": round((count / total_count) * 100, 1),
        }
        for mask, count in mask_counter.most_common(top_masks_count)
    ]

    logger.info(f"Проаналізовано {total_count:,} паролів.")

    return {
        "total_passwords": total_count,
        "weak_passwords": weak_count,
        "weak_percentage": weak_percentage,
        "avg_length": avg_length,
        "top_masks": top_masks,
    }


def run_password_audit(
    wordlist_path: Path,
    output_path: Path | None = None,
    min_length: int = 8,
    top_masks: int = 5,
) -> None:
    stats = analyze_wordlist(wordlist_path, min_length, top_masks)

    print("\n=== Password Dictionary Audit Summary ===")
    print(f"Total Passwords        : {stats['total_passwords']:,}")
    print(
        f"Weak Passwords (<{min_length})   : {stats['weak_passwords']:,} ({stats['weak_percentage']}%)"
    )
    print(f"Average Length         : {stats['avg_length']} characters")
    print(f"\n=== Top-{top_masks} Password Masks ===")

    for idx, item in enumerate(stats["top_masks"], start=1):
        print(f"{idx}. {item['mask']:<35}: {item['count']:,} ({item['percentage']}%)")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(stats, f, indent=4, ensure_ascii=False)
        logger.info(f"Статистику словника збережено у {output_path}")

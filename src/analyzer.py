import re
from pathlib import Path

LOG_PATH = Path("logs/auth.log")


def read_log(path: Path):
    """
    Читает лог-файл и возвращает список строк.
    """
		
    with open(path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    return lines



def find_failed_password(lines):
    """
    Ищет строки Failed password и извлекает IP.
    """

    failed_count = 0

    pattern = re.compile(
        r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
    )

    print("\n===== Failed password =====\n")

    for line in lines:

        match = pattern.search(line)

        if match:
            ip = match.group(1)

            print(ip)

            failed_count += 1

    print("\n---------------------------")
    print(f"Всего Failed password: {failed_count}")


def main():
    lines = read_log(LOG_PATH)

    print(f"Всего строк: {len(lines)}")
    print("\nНеудачные попытки входа:\n")

    find_failed_password(lines)


if __name__ == "__main__":
    main()
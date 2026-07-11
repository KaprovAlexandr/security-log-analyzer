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
    Ищет все строки с Failed password.
    """

    failed_count = 0

    print("\n===== Failed password =====\n")

    for line in lines:

        if "Failed password" in line:
            print(line.strip())
            failed_count += 1

    print("\n---------------------------")
    print(f"Всего Failed password: {failed_count}")


def main():
    lines = read_log(LOG_PATH)

    print(f"Всего строк: {len(lines)}")

    find_failed_password(lines)


if __name__ == "__main__":
    main()
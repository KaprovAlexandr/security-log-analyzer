from pathlib import Path

LOG_PATH = Path("logs/auth.log")


def read_log(path: Path):
    with open(path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    return lines


def main():
    lines = read_log(LOG_PATH)

    print(f"Всего строк: {len(lines)}")
    print("\nПервые строки:\n")

    for line in lines:
        print(line.strip())


if __name__ == "__main__":
    main()
import re
from pathlib import Path
from collections import Counter

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
    Ищет Failed password и считает количество попыток для каждого IP.
    """

    pattern = re.compile(
        r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
    )

    ip_counter = Counter()
    failed_count = 0

    for line in lines:
        match = pattern.search(line)

        if match:
            ip = match.group(1)

            ip_counter[ip] += 1
            failed_count += 1

    print("\n===== Failed password =====\n")

    for ip, count in ip_counter.most_common(10):

    	if count >= 5:
        	print(f"{ip} -> {count} попыток  BRUTE FORCE")

    	else:
        	print(f"{ip} -> {count} попыток")

    print("\n---------------------------")
    print(f"Всего Failed password: {failed_count}")



def find_success_login(lines):
    """
    Ищет успешные входы.
    """

    pattern = re.compile(
        r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)"
    )

    success_counter = 0

    print("\n===== Successful Login =====\n")

    for line in lines:

        match = pattern.search(line)

        if match:
            user = match.group(1)
            ip = match.group(2)

            print(f"{ip} -> пользователь {user}")

            success_counter += 1

    print("\n---------------------------")
    print(f"Всего успешных входов: {success_counter}")



def main():
    lines = read_log(LOG_PATH)

    print(f"Всего строк: {len(lines)}")

    find_failed_password(lines)
    find_success_login(lines)

if __name__ == "__main__":
    main()
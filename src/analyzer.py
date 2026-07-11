import re
import json
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



def correlate_bruteforce_success(lines):
    """
    Ищет успешный вход после серии Failed password.
    """

    failed_pattern = re.compile(
        r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
    )

    success_pattern = re.compile(
        r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)"
    )

    failed_counter = Counter()

    print("\n===== Brute Force Correlation =====\n")

    for line in lines:

        failed_match = failed_pattern.search(line)

        if failed_match:
            ip = failed_match.group(1)
            failed_counter[ip] += 1

        success_match = success_pattern.search(line)

        if success_match:

            user = success_match.group(1)
            ip = success_match.group(2)

            if failed_counter[ip] >= 5:

                print("ВОЗМОЖНЫЙ BRUTE FORCE")
                print(f"IP: {ip}")
                print(f"User: {user}")
                print(f"Failed attempts: {failed_counter[ip]}")
                print()



def find_sudo_activity(lines):
    """
    Ищет использование sudo.
    """

    pattern = re.compile(
        r"sudo:\s+(\w+)\s+:.*COMMAND=(.+)"
    )

    sudo_counter = 0

    print("\n===== SUDO ACTIVITY =====\n")

    for line in lines:

        match = pattern.search(line)

        if match:

            user = match.group(1)
            command = match.group(2)

            print(f"Пользователь: {user}")
            print(f"Команда: {command}")
            print()

            sudo_counter += 1

    print("---------------------------")
    print(f"Всего sudo-команд: {sudo_counter}")



def find_new_users(lines):
    """
    Ищет создание новых пользователей.
    """

    pattern = re.compile(
        r"useradd.*name=(\w+)"
    )

    user_counter = 0

    print("\n===== NEW USERS =====\n")

    for line in lines:

        match = pattern.search(line)

        if match:

            username = match.group(1)

            print(f"Создан пользователь: {username}")

            user_counter += 1

    print("\n---------------------------")
    print(f"Всего новых пользователей: {user_counter}")



def find_ssh_sessions(lines):
    """
    Ищет открытия SSH-сессий.
    """

    pattern = re.compile(
        r"session opened for user (\w+)"
    )

    session_counter = 0

    print("\n===== SSH SESSIONS =====\n")

    for line in lines:

        match = pattern.search(line)

        if match:

            user = match.group(1)

            print(f"Открыта SSH-сессия: {user}")

            session_counter += 1

    print("\n---------------------------")
    print(f"Всего SSH-сессий: {session_counter}")



def find_failed_sudo(lines):
    """
    Ищет неудачные попытки использования sudo.
    """

    failure_pattern = re.compile(
        r"sudo:.*authentication failure"
    )

    incorrect_pattern = re.compile(
        r"sudo:.*incorrect password attempts"
    )

    failed_counter = 0

    print("\n===== FAILED SUDO =====\n")

    for line in lines:

        if failure_pattern.search(line):

            print("Authentication failure")
            print(line.strip())
            print()

            failed_counter += 1

        elif incorrect_pattern.search(line):

            print("Incorrect password attempts")
            print(line.strip())
            print()

            failed_counter += 1

    print("---------------------------")
    print(f"Всего неудачных sudo: {failed_counter}")



def find_root_logins(lines):
    """
    Ищет успешные входы под root.
    """

    pattern = re.compile(
        r"Accepted password for root from (\d+\.\d+\.\d+\.\d+)"
    )

    root_counter = 0

    print("\n===== ROOT LOGIN =====\n")

    for line in lines:

        match = pattern.search(line)

        if match:

            ip = match.group(1)

            print("ВНИМАНИЕ! Вход под root")
            print(f"IP: {ip}")
            print()

            root_counter += 1

    print("---------------------------")
    print(f"Всего входов под root: {root_counter}")



def export_results():
    """
    Сохраняет результаты анализа в JSON.
    """

    results = {
        "log_file": str(LOG_PATH),
        "status": "analysis completed"
    }

    with open("results.json", "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)

    print("\nРезультаты сохранены в results.json")



def main():
    lines = read_log(LOG_PATH)

    print(f"Всего строк: {len(lines)}")

    find_failed_password(lines)
    find_success_login(lines)
    correlate_bruteforce_success(lines)
    find_sudo_activity(lines)
    find_new_users(lines)
    find_ssh_sessions(lines)
    find_failed_sudo(lines)
    find_root_logins(lines)
    
    export_results()




if __name__ == "__main__":
    main()
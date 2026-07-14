import re
import json
from pathlib import Path
from collections import Counter
from colorama import init, Fore, Style

init(autoreset=True)

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

    print(f"\n{Fore.BLUE}{Style.BRIGHT}===== Failed password ====={Style.RESET_ALL}\n")

    for ip, count in ip_counter.most_common(10):

        if count >= 5:
            print(
                f"{Fore.RED}{Style.BRIGHT}{ip} -> {count} попыток  BRUTE FORCE{Style.RESET_ALL}"
            )
        else:
            print(f"{ip} -> {count} попыток")

    print("\n---------------------------")
    print(f"Всего Failed password: {failed_count}")

    return {
        "total": failed_count,
        "top_ips": dict(ip_counter)
    }


def find_success_login(lines):
    """
    Ищет успешные входы.
    """

    pattern = re.compile(
        r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)"
    )

    success_counter = 0
    success_logins = []

    print(f"\n{Fore.BLUE}{Style.BRIGHT}===== Successful Login ====={Style.RESET_ALL}\n")

    for line in lines:

        match = pattern.search(line)

        if match:
            user = match.group(1)
            ip = match.group(2)

            print(
                f"{Fore.GREEN}{ip} -> пользователь {user}{Style.RESET_ALL}"
            )

            success_logins.append({
                "user": user,
                "ip": ip
            })

            success_counter += 1

    print("\n---------------------------")
    print(f"Всего успешных входов: {success_counter}")

    return {
        "total": success_counter,
        "logins": success_logins
    }


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

    print(f"\n{Fore.BLUE}{Style.BRIGHT}===== Brute Force Correlation ====={Style.RESET_ALL}\n")

    brute_force_events = []

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

                print(
                    f"{Fore.RED}{Style.BRIGHT}ВОЗМОЖНЫЙ BRUTE FORCE{Style.RESET_ALL}"
                )
                print(f"{Fore.RED}IP: {ip}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}User: {user}{Style.RESET_ALL}")
                print(
                    f"{Fore.RED}Failed attempts: {failed_counter[ip]}{Style.RESET_ALL}"
                )
                print()

                brute_force_events.append({
                    "ip": ip,
                    "user": user,
                    "failed_attempts": failed_counter[ip]
                })

    return brute_force_events


def find_sudo_activity(lines):
    """
    Ищет использование sudo.
    """

    pattern = re.compile(
        r"sudo:\s+(\w+)\s+:.*COMMAND=(.+)"
    )

    sudo_counter = 0
    commands = []

    print(f"\n{Fore.BLUE}{Style.BRIGHT}===== SUDO ACTIVITY ====={Style.RESET_ALL}\n")

    for line in lines:

        match = pattern.search(line)

        if match:

            user = match.group(1)
            command = match.group(2)

            print(
                f"{Fore.YELLOW}Пользователь: {user}{Style.RESET_ALL}"
            )
            print(
                f"{Fore.YELLOW}Команда: {command}{Style.RESET_ALL}"
            )
            print()

            commands.append({
                "user": user,
                "command": command
            })

            sudo_counter += 1

    print("---------------------------")
    print(f"Всего sudo-команд: {sudo_counter}")

    return {
        "total": sudo_counter,
        "commands": commands
    }


def find_new_users(lines):
    """
    Ищет создание новых пользователей.
    """

    pattern = re.compile(
        r"useradd.*name=(\w+)"
    )

    user_counter = 0
    users = []

    print(f"\n{Fore.BLUE}{Style.BRIGHT}===== NEW USERS ====={Style.RESET_ALL}\n")

    for line in lines:

        match = pattern.search(line)

        if match:

            username = match.group(1)

            print(
                f"{Fore.CYAN}Создан пользователь: {username}{Style.RESET_ALL}"
            )

            users.append(username)

            user_counter += 1

    print("\n---------------------------")
    print(f"Всего новых пользователей: {user_counter}")

    return {
        "total": user_counter,
        "users": users
    }


def find_ssh_sessions(lines):
    """
    Ищет открытия SSH-сессий.
    """

    pattern = re.compile(
        r"session opened for user (\w+)"
    )

    session_counter = 0
    sessions = []

    print(f"\n{Fore.BLUE}{Style.BRIGHT}===== SSH SESSIONS ====={Style.RESET_ALL}\n")

    for line in lines:

        match = pattern.search(line)

        if match:

            user = match.group(1)

            print(
                f"{Fore.CYAN}Открыта SSH-сессия: {user}{Style.RESET_ALL}"
            )

            sessions.append(user)

            session_counter += 1

    print("\n---------------------------")
    print(f"Всего SSH-сессий: {session_counter}")

    return {
        "total": session_counter,
        "users": sessions
    }


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
    events = []

    print(f"\n{Fore.BLUE}{Style.BRIGHT}===== FAILED SUDO ====={Style.RESET_ALL}\n")

    for line in lines:

        if failure_pattern.search(line):

            print(
                f"{Fore.RED}Authentication failure{Style.RESET_ALL}"
            )
            print(line.strip())
            print()

            events.append(line.strip())

            failed_counter += 1

        elif incorrect_pattern.search(line):

            print(
                f"{Fore.RED}Incorrect password attempts{Style.RESET_ALL}"
            )
            print(line.strip())
            print()

            events.append(line.strip())

            failed_counter += 1

    print("---------------------------")
    print(f"Всего неудачных sudo: {failed_counter}")

    return {
        "total": failed_counter,
        "events": events
    }


def find_root_logins(lines):
    """
    Ищет успешные входы под root.
    """

    pattern = re.compile(
        r"Accepted password for root from (\d+\.\d+\.\d+\.\d+)"
    )

    root_counter = 0
    root_ips = []

    print(f"\n{Fore.BLUE}{Style.BRIGHT}===== ROOT LOGIN ====={Style.RESET_ALL}\n")

    for line in lines:

        match = pattern.search(line)

        if match:

            ip = match.group(1)

            print(
                f"{Fore.RED}{Style.BRIGHT}ВНИМАНИЕ! ВХОД ПОД ROOT{Style.RESET_ALL}"
            )
            print(
                f"{Fore.RED}IP: {ip}{Style.RESET_ALL}"
            )
            print()

            root_ips.append(ip)

            root_counter += 1

    print("---------------------------")
    print(f"Всего входов под root: {root_counter}")

    return {
        "total": root_counter,
        "ips": root_ips
    }


def export_results(results):
    """
    Сохраняет результаты анализа в JSON.
    """

    with open("results.json", "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)

    print("\nРезультаты сохранены в results.json")


def main():

    lines = read_log(LOG_PATH)

    print(f"Всего строк: {len(lines)}")

    failed = find_failed_password(lines)
    success = find_success_login(lines)
    brute = correlate_bruteforce_success(lines)
    sudo = find_sudo_activity(lines)
    users = find_new_users(lines)
    sessions = find_ssh_sessions(lines)
    failed_sudo = find_failed_sudo(lines)
    root = find_root_logins(lines)

    results = {
        "log_file": str(LOG_PATH),
        "failed_passwords": failed,
        "successful_logins": success,
        "brute_force_events": brute,
        "sudo_activity": sudo,
        "new_users": users,
        "ssh_sessions": sessions,
        "failed_sudo": failed_sudo,
        "root_logins": root
    }

    export_results(results)


if __name__ == "__main__":
    main()
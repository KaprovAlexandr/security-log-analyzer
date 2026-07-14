import re
import json
import argparse
from pathlib import Path
from collections import Counter
from colorama import init, Fore, Style

init(autoreset=True)
USE_COLOR = True

LOG_PATH = Path("logs/auth.log")


def color(text, color_code="", style_code=""):
    """
    Возвращает цветной текст, если цвет включён.
    """

    if not USE_COLOR:
        return text

    return f"{color_code}{style_code}{text}{Style.RESET_ALL}"


def parse_arguments():
    """
    Обрабатывает аргументы командной строки.
    """

    parser = argparse.ArgumentParser(
        description="Security Log Analyzer"
    )

    parser.add_argument(
        "-f",
        "--file",
        default="logs/auth.log",
        help="Путь к log-файлу"
    )

    parser.add_argument(
        "-j",
        "--json",
        default="results.json",
        help="Имя JSON-файла для сохранения результатов"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Отключить цветной вывод"
    )

    return parser.parse_args()


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

    print("\n" + color("===== Failed password =====", Fore.BLUE, Style.BRIGHT) + "\n")

    for ip, count in ip_counter.most_common(10):

        if count >= 5:
            print(
                color(
                    f"{ip} -> {count} попыток  BRUTE FORCE",
                    Fore.RED,
                    Style.BRIGHT
                )
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

    print(
        "\n" +
        color(
            "===== Successful Login =====",
            Fore.BLUE,
            Style.BRIGHT
        ) +
        "\n"
    )

    for line in lines:

        match = pattern.search(line)

        if match:
            user = match.group(1)
            ip = match.group(2)

            print(
                color(
                    f"{ip} -> пользователь {user}",
                    Fore.GREEN
                )
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

    print(
        "\n" +
        color(
            "===== Brute Force Correlation =====",
            Fore.BLUE,
            Style.BRIGHT
        ) +
        "\n"
    )

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
                    color(
                        "ВОЗМОЖНЫЙ BRUTE FORCE",
                        Fore.RED,
                        Style.BRIGHT
                    )
                )

                print(
                    color(
                        f"IP: {ip}",
                        Fore.RED
                    )
                )

                print(
                    color(
                        f"User: {user}",
                        Fore.YELLOW
                    )
                )

                print(
                    color(
                        f"Failed attempts: {failed_counter[ip]}",
                        Fore.RED
                    )
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

    print(
        "\n" +
        color(
            "===== SUDO ACTIVITY =====",
            Fore.BLUE,
            Style.BRIGHT
        ) +
        "\n"
    )

    for line in lines:

        match = pattern.search(line)

        if match:

            user = match.group(1)
            command = match.group(2)

            print(
                color(
                    f"Пользователь: {user}",
                    Fore.YELLOW
                )
            )

            print(
                color(
                    f"Команда: {command}",
                    Fore.YELLOW
                )
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

    print(
        "\n" +
        color(
            "===== NEW USERS =====",
            Fore.BLUE,
            Style.BRIGHT
        ) +
        "\n"
    )

    for line in lines:

        match = pattern.search(line)

        if match:

            username = match.group(1)

            print(
                color(
                    f"Создан пользователь: {username}",
                    Fore.CYAN
                )
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

    print(
        "\n" +
        color(
            "===== SSH SESSIONS =====",
            Fore.BLUE,
            Style.BRIGHT
        ) +
        "\n"
    )

    for line in lines:

        match = pattern.search(line)

        if match:

            user = match.group(1)

            print(
                color(
                    f"Открыта SSH-сессия: {user}",
                    Fore.CYAN
                )
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

    print(
        "\n" +
        color(
            "===== FAILED SUDO =====",
            Fore.BLUE,
            Style.BRIGHT
        ) +
        "\n"
    )

    for line in lines:

        if failure_pattern.search(line):

            print(
                color(
                    "Authentication failure",
                    Fore.RED
                )
            )
            print(line.strip())
            print()

            events.append(line.strip())

            failed_counter += 1

        elif incorrect_pattern.search(line):

            print(
                color(
                    "Incorrect password attempts",
                    Fore.RED
                )
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

    print(
        "\n" +
        color(
            "===== ROOT LOGIN =====",
            Fore.BLUE,
            Style.BRIGHT
        ) +
        "\n"
    )

    for line in lines:

        match = pattern.search(line)

        if match:

            ip = match.group(1)

            print(
                color(
                    "ВНИМАНИЕ! ВХОД ПОД ROOT",
                    Fore.RED,
                    Style.BRIGHT
                )
            )

            print(
                color(
                    f"IP: {ip}",
                    Fore.RED
                )
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


def export_results(results, output_file):
    """
    Сохраняет результаты анализа в JSON.
    """

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)

    print(f"\nРезультаты сохранены в {output_file}")


def main():

    args = parse_arguments()

    global USE_COLOR
    USE_COLOR = not args.no_color

    log_path = Path(args.file)
    output_file = args.json
    lines = read_log(log_path)

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
        "log_file": str(log_path),
        "failed_passwords": failed,
        "successful_logins": success,
        "brute_force_events": brute,
        "sudo_activity": sudo,
        "new_users": users,
        "ssh_sessions": sessions,
        "failed_sudo": failed_sudo,
        "root_logins": root
    }

    export_results(results, output_file)


if __name__ == "__main__":
    main()
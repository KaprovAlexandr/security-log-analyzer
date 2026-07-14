# Security Log Analyzer

## Цель

Автоматизация анализа логов Linux для обнаружения подозрительной активности.

## Возможности

- Анализ Failed password
- Анализ Successful login
- Выявление возможного Brute Force
- Корреляция успешного входа после Brute Force
- Анализ активности sudo
- Поиск новых пользователей
- Анализ SSH-сессий
- Поиск неудачных sudo
- Поиск входов под root
- Экспорт результатов в JSON
- Цветной вывод результатов
- CLI-команды (-f, --file, -j, --help, --no-color)

## Стек / Инструменты

- Python 3
- argparse
- pathlib
- Counter
- colorama

## Как запустить

Базовый запуск

```bash
python src/analyzer.py
```

Без цветного вывода

```bash
python src/analyzer.py --no-color
```

Указать лог-файл

```bash
python src/analyzer.py -f logs/auth.log
```

или

```bash
python src/analyzer.py --file logs/auth.log
```

Указать имя JSON-отчёта

```bash
python src/analyzer.py -j report.json
```

Справочная информация

```bash
python src/analyzer.py --help
```

## Что я узнал

- Научился анализировать логи Linux и выявлять признаки подозрительной активности.
- Освоил использование регулярных выражений для извлечения событий безопасности из логов.
- Узнал, как именно можно автоматизировать задачи SOC с помощью Python.

## Скриншоты / Результаты

### Терминал

![Terminal Output](/assets/terminal-output.png)

### JSON-файл

![JSON Report](/assets/json-report.png)

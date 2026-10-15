#!/usr/bin/env python
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    os.environ.setdefault("DJANGO_CONFIGURATION", "Development")
    try:
        from configurations.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "django-configurations не установлен. Запустите: uv sync"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
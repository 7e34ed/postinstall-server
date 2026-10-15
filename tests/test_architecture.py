"""Тесты архитектурных инвариантов.

Проверяют, что слои не зависят друг от друга циклически.
"""
import ast
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _imports_in(path: Path) -> list[str]:
    """Все from-импорты из файла, включая вложенные в функции."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    result = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            result.append(node.module)
    return result


def test_core_does_not_depend_on_apps():
    """core не должен импортировать наши app'ы."""
    core = REPO_ROOT / "apps" / "core"
    forbidden = ("apps.access", "apps.secrets", "apps.inventory",
                 "apps.config", "apps.deploy", "apps.credentials",
                 "apps.dashboard", "apps.api")
    for py in core.rglob("*.py"):
        for imp in _imports_in(py):
            for f in forbidden:
                assert not imp.startswith(f), \
                    f"{py}: недопустимый импорт {imp}"


def test_secrets_does_not_depend_on_access():
    """secrets не знает про access."""
    secrets = REPO_ROOT / "apps" / "secrets"
    for py in secrets.rglob("*.py"):
        for imp in _imports_in(py):
            assert not imp.startswith("apps.access"), \
                f"{py}: недопустимый импорт {imp}"


def test_inventory_does_not_depend_on_access_or_secrets():
    """inventory не знает про access, не использует secrets.services."""
    inv = REPO_ROOT / "apps" / "inventory"
    for py in inv.rglob("*.py"):
        for imp in _imports_in(py):
            assert not imp.startswith("apps.access"), \
                f"{py}: недопустимый импорт {imp}"
            assert not imp.startswith("apps.secrets.services"), \
                f"{py}: недопустимый импорт {imp}"
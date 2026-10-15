from __future__ import annotations

from abc import ABC, abstractmethod


class SecretBackendError(Exception):
    pass


class SecretNotFound(SecretBackendError):
    pass


class SecretBackend(ABC):
    """Абстракция над хранилищем секретов.

    Все методы работают с "path" — уникальным путём к секрету.
    Формат пути зависит от бэкенда:
      * local:    логический ключ, например "domains/example.local/domain_password"
      * openbao:  <mount>/<path>, например "psi/data/domains/example.local/password"
    """

    name: str = ""

    @abstractmethod
    def get(self, path: str, key: str) -> str:
        """Вернуть значение. Бросает SecretNotFound, если нет."""

    @abstractmethod
    def set(self, path: str, key: str, value: str) -> None:
        """Записать значение (создать или обновить)."""

    @abstractmethod
    def delete(self, path: str) -> None:
        """Удалить весь секрет по path."""

    @abstractmethod
    def exists(self, path: str) -> bool:
        """Проверить наличие секрета."""

    def health(self) -> dict:
        """Проверка работоспособности бэкенда."""
        try:
            self.get("__healthcheck__", "key")
        except SecretNotFound:
            return {"status": "ok"}
        except SecretBackendError as exc:
            return {"status": "error", "detail": str(exc)}
        return {"status": "ok"}

    def iter_secrets(self, prefix: str = ""):
        """Итератор по всем секретам.

        Yield: (path, key, value).

        prefix — фильтр по началу path (например, "credentials/").

        Реализация опциональна: backend без поддержки list возвращает
        пустой итератор и логирует warning. Миграция в такой backend
        работать не будет, но обычные get/set работают.
        """
        return
        yield  # noqa
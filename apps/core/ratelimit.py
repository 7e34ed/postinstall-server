"""Простой rate-limit через Django cache (Redis).

Ключ: namespace:identifier:window_start.
Значения — счётчики с TTL.

Подходит для:
  * ограничения login attempts;
  * ограничения sensitive-действий (backend secrets, role assign);
  * API-запросов по токену.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from django.core.cache import cache


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_in: int          # секунд до сброса окна
    limit: int
    current: int


def hit(key: str, *, limit: int, window: int) -> RateLimitResult:
    """Увеличить счётчик и вернуть результат.

    key       — уникальный идентификатор (например, f"login:{ip}")
    limit     — максимальное число операций в окне
    window    — длина окна в секундах
    """
    now = int(time.time())
    window_start = now - (now % window)
    cache_key = f"rl:{key}:{window_start}"

    try:
        current = cache.get(cache_key, 0)
    except Exception:
        # Если кэш недоступен — не блокируем (fail-open).
        # Для критичных рубильников — fail-closed через отдельные настройки.
        return RateLimitResult(
            allowed=True, remaining=limit, reset_in=0,
            limit=limit, current=0,
        )

    if current >= limit:
        reset_in = window - (now - window_start)
        return RateLimitResult(
            allowed=False, remaining=0, reset_in=reset_in,
            limit=limit, current=current,
        )

    try:
        cache.set(cache_key, current + 1, timeout=window + 1)
    except Exception:
        pass

    return RateLimitResult(
        allowed=True,
        remaining=max(0, limit - current - 1),
        reset_in=window - (now - window_start),
        limit=limit,
        current=current + 1,
    )


def check(key: str, *, limit: int, window: int) -> RateLimitResult:
    """Проверить без инкремента."""
    now = int(time.time())
    window_start = now - (now % window)
    cache_key = f"rl:{key}:{window_start}"
    try:
        current = cache.get(cache_key, 0)
    except Exception:
        current = 0
    reset_in = window - (now - window_start)
    return RateLimitResult(
        allowed=current < limit, remaining=max(0, limit - current - 1),
        reset_in=reset_in, limit=limit, current=current,
    )


def reset(key: str) -> None:
    """Сбросить счётчики во всех окнах (по префиксу)."""
    # В Django cache нет «удалить по шаблону» — обходим через префикс
    # текущего и предыдущего окна.
    now = int(time.time())
    # Пробуем окна разной длины — не идеально, но достаточно
    for w in (60, 300, 900, 3600):
        ws = now - (now % w)
        cache.delete(f"rl:{key}:{ws}")

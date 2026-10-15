"""Клиент RADIUS для HOTP-аутентификации.

Использует pyrad. Отправляет Access-Request с User-Name и User-Password.
Формат User-Password зависит от настройки Aladdin:

  * concat: <пароль><OTP> (классический для Aladdin HOTP)
  * password_only: только пароль; OTP вынесен в отдельный шаг
    (не поддерживается в текущей версии)

Возвращает dataclass RadiusResult с кодом и опциональным сообщением.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any

import pyrad.packet
from loguru import logger
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary

# Встроенный минимальный dictionary. Полный RADIUS dictionary не нужен:
# мы отправляем только стандартные атрибуты User-Name и User-Password.
MINIMAL_DICTIONARY = """
ATTRIBUTE User-Name       1 string
ATTRIBUTE User-Password   2 string
ATTRIBUTE Reply-Message   18 string
ATTRIBUTE Session-Timeout 27 integer
ATTRIBUTE Auth-Type       1000 integer
"""


class RadiusError(Exception):
    pass


class RadiusTimeout(RadiusError):
    pass


class RadiusUnreachable(RadiusError):
    pass


@dataclass
class RadiusResult:
    accepted: bool
    code: int                          # pyrad.packet.AccessAccept / Reject
    message: str = ""                  # Reply-Message
    session_timeout: int | None = None
    attributes: dict[str, Any] | None = None


@dataclass
class RadiusConfig:
    host: str
    port: int = 1812
    secret: str = ""
    nas_identifier: str = ""
    timeout: int = 3
    retries: int = 2
    dictionary_path: str = ""          # опционально


def _build_dictionary(cfg: RadiusConfig) -> Dictionary:
    if cfg.dictionary_path:
        try:
            return Dictionary(cfg.dictionary_path)
        except Exception as exc:
            logger.warning(
                f"radius: не удалось загрузить {cfg.dictionary_path}: {exc}. "
                f"Использую встроенный минимальный словарь."
            )
    return Dictionary(MINIMAL_DICTIONARY)


def authenticate(cfg: RadiusConfig, *, username: str, password: str) -> RadiusResult:
    """Отправить Access-Request.

    Возвращает RadiusResult с accepted=True при Access-Accept.
    Бросает RadiusTimeout при timeout, RadiusUnreachable при сетевой ошибке.
    """
    
    if not cfg.host or not cfg.secret:
        raise RadiusError("radius: host и secret обязательны")

    dict_obj = _build_dictionary(cfg)

    try:
        client = Client(
            server=cfg.host,
            authport=cfg.port,
            secret=cfg.secret.encode(),
            dict=dict_obj,
        )
    except Exception as exc:
        raise RadiusError(f"radius: не удалось создать клиент: {exc}") from exc

    client.timeout = cfg.timeout
    client.retries = cfg.retries

    req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest)
    req["User-Name"] = username
    req["User-Password"] = req.PwCrypt(password)

    if cfg.nas_identifier:
        try:
            req["NAS-Identifier"] = cfg.nas_identifier
        except KeyError:
            # если словарь не содержит атрибут — пропускаем
            pass

    logger.debug(f"radius: Access-Request for user={username} host={cfg.host}")

    try:
        reply = client.SendPacket(req)
    except Timeout as exc:
        logger.warning(f"radius: timeout для {username} на {cfg.host}")
        raise RadiusTimeout(f"RADIUS timeout: {cfg.host}:{cfg.port}") from exc
    except socket.error as exc:  # noqa: UP024
        logger.error(f"radius: сетевая ошибка {exc}")
        raise RadiusUnreachable(f"RADIUS unreachable: {exc}") from exc
    except Exception as exc:
        logger.exception("radius: неожиданная ошибка")
        raise RadiusError(f"radius: {exc}") from exc

    code = reply.code
    accepted = code == pyrad.packet.AccessAccept

    message = ""
    session_timeout: int | None = None
    try:
        message = str(reply.get("Reply-Message", ""))
    except KeyError:
        pass
    try:
        session_timeout = int(reply.get("Session-Timeout"))
    except (KeyError, ValueError):
        pass

    attrs: dict[str, Any] = {}
    for k, v in reply.items():
        attrs[str(k)] = v

    if accepted:
        logger.info(f"radius: Access-Accept for {username}")
    else:
        logger.info(f"radius: Access-Reject for {username} (code={code})")

    return RadiusResult(
        accepted=accepted,
        code=code,
        message=message,
        session_timeout=session_timeout,
        attributes=attrs,
    )
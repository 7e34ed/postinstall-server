"""Обёртка над ldap3.

Только чтение (bind + search). Никогда не пишет в AD.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from loguru import logger

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException
except ImportError:
    ldap3 = None
    LDAPException = Exception


class LDAPError(Exception):
    pass


class LDAPNotAvailable(LDAPError):
    pass


@dataclass
class LDAPSettings:
    url: str
    base_dn: str
    bind_dn: str
    bind_password: str
    user_filter: str = "(objectClass=user)"
    computer_filter: str = "(objectClass=computer)"
    timeout: int = 5
    use_starttls: bool = False
    verify_tls: bool = True


def _require_ldap3():
    if ldap3 is None:
        raise LDAPNotAvailable(
            "ldap3 не установлен. Установите: pip install ldap3"
        )


class LDAPClient:
    """Клиент LDAP. Все операции — read-only.

    Использование:
        with LDAPClient(settings) as c:
            user = c.find_user_by_email("ivan@company.local")
    """

    def __init__(self, settings: LDAPSettings):
        _require_ldap3()
        self.s = settings
        self._conn = None

    def __enter__(self) -> "LDAPClient":
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self) -> None:
        try:
            server = ldap3.Server(
                self.s.url,
                get_info=ldap3.NONE,
                connect_timeout=self.s.timeout,
                use_ssl=self.s.url.startswith("ldaps://"),
            )
            self._conn = ldap3.Connection(
                server,
                user=self.s.bind_dn or None,
                password=self.s.bind_password or None,
                auto_bind=False,
                receive_timeout=self.s.timeout,
                raise_exceptions=False,
            )
            if not self._conn.open():
                raise LDAPError("не удалось открыть соединение")
            if self.s.use_starttls:
                if not self._conn.start_tls():
                    raise LDAPError("не удалось начать StartTLS")
            if self.s.bind_dn:
                if not self._conn.bind():
                    raise LDAPError(
                        f"bind failed: {self._conn.result.get('description')}"
                    )
            else:
                # anonymous bind
                self._conn.bind()
        except LDAPException as exc:
            raise LDAPError(f"connect: {exc}") from exc

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:
                pass
            self._conn = None

    # --- поиск ---

    def find_user_by_email(self, email: str) -> dict | None:
        """Найти пользователя по mail или userPrincipalName."""
        f = (
            f"(&{self.s.user_filter}"
            f"(|(mail={_ldap_escape(email)})"
            f"(userPrincipalName={_ldap_escape(email)})))"
        )
        return self._search_one(
            f,
            attributes=["sAMAccountName", "cn", "givenName", "sn", "mail",
                        "userPrincipalName", "displayName",
                        "userAccountControl", "memberOf"],
        )

    def find_user_by_sam(self, sam: str) -> dict | None:
        f = f"(&{self.s.user_filter}(sAMAccountName={_ldap_escape(sam)}))"
        return self._search_one(
            f,
            attributes=["sAMAccountName", "cn", "givenName", "sn", "mail",
                        "userPrincipalName", "displayName",
                        "userAccountControl"],
        )

    def list_computers(self, *, ou: str | None = None) -> Iterator[dict]:
        """Итератор по компьютерам AD."""
        base = ou or self.s.base_dn
        f = self.s.computer_filter
        yield from self._search_iter(
            f, base=base,
            attributes=["sAMAccountName", "dNSHostName", "cn",
                        "operatingSystem", "operatingSystemVersion",
                        "userAccountControl", "distinguishedName",
                        "lastLogonTimestamp"],
        )

    # --- низкий уровень ---

    def _search_one(self, filter_: str, *, attributes: list[str]) -> dict | None:
        results = list(self._search_iter(filter_, attributes=attributes,
                                          limit=1))
        return results[0] if results else None

    def _search_iter(self, filter_: str, *, base: str | None = None,
                      attributes: list[str],
                      limit: int = 0) -> Iterator[dict]:
        if self._conn is None:
            raise LDAPError("не подключено")
        base = base or self.s.base_dn
        try:
            self._conn.search(
                search_base=base,
                search_filter=filter_,
                attributes=attributes,
                paged_size=500,
                size_limit=limit,
            )
        except LDAPException as exc:
            raise LDAPError(f"search: {exc}") from exc

        while True:
            for entry in self._conn.entries:
                yield _entry_to_dict(entry)
            if limit or not self._conn.result.get("controls"):
                break
            cookie = (self._conn.result["controls"]
                      .get("1.2.840.113556.1.4.319", {})
                      .get("value", {}).get("cookie"))
            if not cookie:
                break
            self._conn.search(
                search_base=base,
                search_filter=filter_,
                attributes=attributes,
                paged_size=500,
                paged_cookie=cookie,
            )


def _ldap_escape(s: str) -> str:
    """RFC 4515 escape."""
    result = ""
    for c in s:
        if c in r"()*\\\x00":
            result += "\\" + format(ord(c), "02x")
        else:
            result += c
    return result


def _entry_to_dict(entry) -> dict:
    """ldap3 entry → dict, значения — строки или списки строк."""
    out: dict = {"dn": entry.entry_dn}
    for attr in entry.entry_attributes:
        value = entry[attr].value
        if isinstance(value, list):
            out[attr] = [str(v) for v in value]
        else:
            out[attr] = str(value) if value is not None else ""
    return out


# --- helpers для парсинга ---

USER_ACCOUNT_DISABLED = 0x0002
USER_ACCOUNT_LOCKOUT = 0x0010


def is_user_active(attrs: dict) -> bool:
    """Проверить, что учётка в AD не отключена и не заблокирована."""
    uac = attrs.get("userAccountControl", 0)
    try:
        uac_int = int(uac)
    except (TypeError, ValueError):
        return True   # не можем определить — оптимистично
    if uac_int & USER_ACCOUNT_DISABLED:
        return False
    if uac_int & USER_ACCOUNT_LOCKOUT:
        return False
    return True
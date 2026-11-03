"""Уровни Authenticator Assurance Level.

Чистый enum без Django-зависимостей — может использоваться в core,
access, secrets и т.д.
"""
from enum import IntEnum


class AAL(IntEnum):
    NONE = 0
    AAL1 = 1
    AAL2 = 2
    AAL3 = 3

    @property
    def label(self) -> str:
        return {
            AAL.NONE: "не аутентифицирован",
            AAL.AAL1: "AAL1 (пароль)",
            AAL.AAL2: "AAL2 (пароль + TOTP)",
            AAL.AAL3: "AAL3 (пароль + hardware)",
        }[self]

    @classmethod
    def from_str(cls, s: str) -> "AAL":
        m = {
            "aal1": cls.AAL1,
            "aal2": cls.AAL2,
            "aal3": cls.AAL3,
        }
        return m.get((s or "").lower(), cls.NONE)


# Типы факторов, которые засчитываются как hardware для AAL3
AAL3_HARDWARE_TYPES: set[str] = {
    "webauthn",
    "client_cert",
    "rutoken",
}
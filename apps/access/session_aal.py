"""Реэкспорт AAL-сессии из core (обратная совместимость)."""
from apps.core.session_aal import (  # noqa: F401
    SESSION_KEY_AAL,
    SESSION_KEY_AAL_AT,
    _to_str,
    _ttl,
    current_aal,
    current_aal_timestamp,
    is_aal_fresh,
    reset_aal,
    set_aal,
)

def get_auth_source(user) -> str:
    """Вернуть auth_source пользователя. Если настройки нет — local."""
    from .models import UserAuthSettings
    try:
        return user.auth_settings.auth_source
    except UserAuthSettings.DoesNotExist:
        return UserAuthSettings.Source.LOCAL
    except AttributeError:
        return UserAuthSettings.Source.LOCAL
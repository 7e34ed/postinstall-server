import pytest
from django.utils import timezone


# Для добавления ручками в тест
@pytest.fixture
def setup_complete(db):
    """Помечает setup как завершённый — иначе SetupPhaseMiddleware
    редиректит все запросы на /access/setup/.
    """
    from apps.access.models import SuperuserBootstrap
    bootstrap = SuperuserBootstrap.get()
    if not bootstrap.is_setup_complete:
        bootstrap.is_setup_complete = True
        bootstrap.save(update_fields=["is_setup_complete"])
    return bootstrap


@pytest.fixture(autouse=True)
def _setup_phase_complete(request, db):
    """По умолчанию setup завершён. Тесты, которые проверяют
    поведение до setup, помечаются @pytest.mark.no_setup.
    """
    if "no_setup" in request.keywords:
        yield
        return
    from apps.access.models import SuperuserBootstrap
    bootstrap = SuperuserBootstrap.get()
    if not bootstrap.is_setup_complete:
        bootstrap.is_setup_complete = True
        bootstrap.save(update_fields=["is_setup_complete"])
    yield


# Регистрируем маркер
def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "no_setup: тест проверяет поведение до завершения setup-фазы",
    )


def login_with_aal(client, user, *, aal="aal2"):
    """Залогинить с заданным AAL (по умолчанию — AAL2)."""
    client.force_login(user)
    session = client.session
    session["psi_aal"] = aal
    session["psi_aal_at"] = timezone.now().isoformat()
    session.save()
    return client


@pytest.fixture
def login_with_aal_fixture():
    return login_with_aal


@pytest.fixture
def mfa_user(db):
    """Пользователь с TOTP (для тестов AAL2)."""
    from allauth.mfa.models import Authenticator
    from django.contrib.auth import get_user_model

    User = get_user_model()
    u = User.objects.create_user(
        username="mfa_user", password="Test-Pass-AAL2-99",
    )
    Authenticator.objects.create(
        user=u, type=Authenticator.Type.TOTP, data={},
    )
    return u


# tests/conftest.py
@pytest.fixture(autouse=True)
def _recovery_kit_dir(settings, tmp_path):
    settings.ACCESS_RECOVERY_KIT_DIR = str(tmp_path / "recovery")
    yield


@pytest.fixture(autouse=True)
def _clean_recovery_dir():
    import shutil
    from pathlib import Path
    p = Path("/tmp/postinstall-recovery-test")
    if p.exists():
        shutil.rmtree(p)
    yield
    if p.exists():
        shutil.rmtree(p)
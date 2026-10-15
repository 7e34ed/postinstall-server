import pytest

from apps.config.models import (
    Certificate, ConfigProfile, ConfigRevision, Package, Repository,
)
from apps.config.services import resolve_for_host, resolve_hardening_for_host
from apps.inventory.models import Domain, Host, HostSet


@pytest.fixture
def domain(db):
    return Domain.objects.create(name="test.local")


@pytest.fixture
def host_set(domain):
    return HostSet.objects.create(
        domain=domain,
        name="web",
        platform="linux.debian",
        common_config={
            "general": {"allowed_ips": ["10.0.0.0/8"], "allowed_ports": [22]},
            "fail2ban": {"enabled": True, "jails": ["sshd"]},
        },
    )


@pytest.fixture
def host(host_set):
    return Host.objects.create(
        domain=host_set.domain,
        host_set=host_set,
        hostname="web1",
    )


@pytest.mark.django_db
def test_empty_profile_resolution(host):
    settings = resolve_for_host(host)
    assert settings["general"]["allowed_ports"] == [22]
    assert settings["host"]["hostname"] == "web1"


@pytest.mark.django_db
def test_profile_extra_ports(host_set, host):
    p = ConfigProfile.objects.create(
        name="nginx", slug="nginx", platform="any",
        extra_ports=[80, 443],
        jails=["nginx"],
        packages=["nginx"],
    )
    p.save()
    from apps.config.models import HostSetProfile
    HostSetProfile.objects.create(host_set=host_set, profile=p, order=10)

    settings = resolve_for_host(host)
    assert sorted(settings["general"]["allowed_ports"]) == [22, 80, 443]
    assert "nginx" in settings["fail2ban"]["jails"]
    assert settings["packages"]["apt"] == ["nginx"]


@pytest.mark.django_db
def test_profile_ordering(host_set, host):
    p1 = ConfigProfile.objects.create(name="A", slug="a", platform="any",
                                      extra_ports=[80])
    p2 = ConfigProfile.objects.create(name="B", slug="b", platform="any",
                                      extra_ports=[443])
    from apps.config.models import HostSetProfile
    HostSetProfile.objects.create(host_set=host_set, profile=p2, order=20)
    HostSetProfile.objects.create(host_set=host_set, profile=p1, order=10)

    settings = resolve_for_host(host)
    assert settings["general"]["allowed_ports"] == [22, 80, 443]


@pytest.mark.django_db
def test_host_extra_profile_overrides_set(host_set, host):
    p_set = ConfigProfile.objects.create(name="Set", slug="set", platform="any",
                                         extra_ports=[80])
    p_host = ConfigProfile.objects.create(
        name="Host", slug="host", platform="any",
        settings={"fail2ban": {"enabled": False}},
    )
    from apps.config.models import HostExtraProfile, HostSetProfile
    HostSetProfile.objects.create(host_set=host_set, profile=p_set, order=10)
    HostExtraProfile.objects.create(host=host, profile=p_host, order=10)

    settings = resolve_for_host(host)
    assert settings["fail2ban"]["enabled"] is False


@pytest.mark.django_db
def test_revision_created_on_save(host):
    p = ConfigProfile.objects.create(name="X", slug="x", platform="any")
    assert ConfigRevision.objects.filter(profile=p).count() == 1

    p.name = "X2"
    p.save()
    p.refresh_from_db()
    assert p.version == 2
    assert ConfigRevision.objects.filter(profile=p).count() == 2


@pytest.mark.django_db
def test_profile_with_repositories_and_certificates(host_set, host):
    r = Repository.objects.create(
        name="internal", platform="linux.debian",
        url="http://repo.local/debian", components="stable main",
    )
    c = Certificate.objects.create(name="internal-ca.crt",
                                   content_b64="ZmFrZQ==")
    p = ConfigProfile.objects.create(name="Base", slug="base", platform="any")
    p.repositories.add(r)
    p.certificates.add(c)

    from apps.config.models import HostSetProfile
    HostSetProfile.objects.create(host_set=host_set, profile=p)

    settings = resolve_for_host(host)
    assert settings["repositories"]["items"][0]["name"] == "internal"
    assert settings["certificates"]["items"][0]["name"] == "internal-ca.crt"


@pytest.mark.django_db
def test_hardening_profiles(host_set, host):
    p1 = ConfigProfile.objects.create(
        name="H1", slug="h1", platform="any",
        hardening={"mode": "apply", "checks": [
            {"id": "sysctl.foo", "type": "sysctl", "params": {}, "autofix": True},
        ]},
    )
    p2 = ConfigProfile.objects.create(
        name="H2", slug="h2", platform="any",
        hardening={"checks": [
            {"id": "sysctl.bar", "type": "sysctl", "params": {}, "autofix": False},
        ]},
    )
    from apps.config.models import HostSetProfile
    HostSetProfile.objects.create(host_set=host_set, profile=p1, order=10)
    HostSetProfile.objects.create(host_set=host_set, profile=p2, order=20)

    result = resolve_hardening_for_host(host)
    ids = {c["id"] for c in result["checks"]}
    assert ids == {"sysctl.foo", "sysctl.bar"}
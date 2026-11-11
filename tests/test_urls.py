import pytest


@pytest.mark.parametrize("url,expected_name", [
    ("/admin/secrets/items/a/b/delete/", "secrets:item-delete"),
    ("/admin/secrets/items/a/b/keys/extra/delete/", "secrets:item-key-delete"),
    ("/admin/secrets/items/a/b/grant/", "secrets:grant-create"),
    ("/admin/secrets/items/a/b/", "secrets:item-edit"),
])
def test_url_routing(url, expected_name):
    from django.urls import resolve
    match = resolve(url)
    assert match.view_name == expected_name
    # kwargs — проверить, что path/key правильные
    if expected_name == "secrets:item-key-delete":
        assert match.kwargs == {"path": "a/b", "key": "extra"}
    if expected_name == "secrets:item-delete":
        assert match.kwargs == {"path": "a/b"}
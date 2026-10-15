"""Кастомизация allauth для postinstall."""
from __future__ import annotations

from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.forms import LoginForm
from django.urls import reverse


class AccountAdapter(DefaultAccountAdapter):
    """Запрещаем свободную регистрацию (всё через инвайты)."""

    def is_open_for_signup(self, request) -> bool:
        return False

    def get_login_redirect_url(self, request) -> str:
        return reverse("dashboard:index")

    def get_logout_redirect_url(self, request) -> str:
        return reverse("account_login")


class StrictLoginForm(LoginForm):
    """Логин-форма без remember-me."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "remember" in self.fields:
            self.fields.pop("remember")
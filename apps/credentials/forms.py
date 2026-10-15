from django import forms

from .models import Credential


class CredentialForm(forms.ModelForm):
    password_value = forms.CharField(
        required=False, widget=forms.PasswordInput(render_value=False),
        label="Пароль",
    )
    ssh_key_value = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 12}),
        label="Приватный SSH-ключ",
    )
    passphrase_value = forms.CharField(
        required=False, widget=forms.PasswordInput(render_value=False),
        label="Passphrase SSH-ключа",
    )

    class Meta:
        model = Credential
        fields = ["name", "kind", "description", "username",
                  "domain", "host_set", "host", "is_active", "tags"]

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def save(self, commit=True):
        from apps.secrets.models import SecretRef
        from apps.secrets.services import set_secret

        from .services import create_credential

        if not self.instance.pk:
            cred = create_credential(
                name=self.cleaned_data["name"],
                kind=self.cleaned_data["kind"],
                username=self.cleaned_data.get("username", ""),
                description=self.cleaned_data.get("description", ""),
                domain=self.cleaned_data.get("domain"),
                host_set=self.cleaned_data.get("host_set"),
                host=self.cleaned_data.get("host"),
                password=self.cleaned_data.get("password_value") or None,
                ssh_key=self.cleaned_data.get("ssh_key_value") or None,
                passphrase=self.cleaned_data.get("passphrase_value") or None,
                user=self.user,
            )
            return cred

        cred = super().save(commit=commit)

        def _upsert(path, value, label):
            set_secret(path, "value", value,
                       display_name=f"Credential: {cred.name} ({label})",
                       user=self.user)
            return SecretRef.objects.filter(backend="local", path=path).first()

        pwd = self.cleaned_data.get("password_value")
        if pwd:
            cred.secret_password = _upsert(cred.secret_path_password, pwd, "password")
        key = self.cleaned_data.get("ssh_key_value")
        if key:
            cred.secret_ssh_key = _upsert(cred.secret_path_ssh_key, key, "ssh_key")
        pp = self.cleaned_data.get("passphrase_value")
        if pp:
            cred.secret_passphrase = _upsert(cred.secret_path_passphrase, pp, "passphrase")
        if pwd or key or pp:
            cred.save()

        return cred
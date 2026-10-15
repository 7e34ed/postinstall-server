from django.db import migrations


def forwards(apps, schema_editor):
    SecretRef = apps.get_model("secrets", "SecretRef")
    User = apps.get_model("auth", "User")

    fallback = (
        User.objects.filter(is_superuser=True, is_active=True)
        .order_by("pk").first()
    )

    for ref in SecretRef.objects.filter(owner__isnull=True):
        ref.owner_id = ref.created_by_id or (fallback.pk if fallback else None)
        if ref.owner_id:
            ref.save(update_fields=["owner"])


def backwards(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("secrets", "0002_secretref"),
    ]
    operations = [
        migrations.RunPython(forwards, backwards),
    ]
from django.db import migrations


def forwards(apps, schema_editor):
    User = apps.get_model("auth", "User")
    SuperuserBootstrap = apps.get_model("access", "SuperuserBootstrap")
    RoleAssignment = apps.get_model("access", "RoleAssignment")

    # Создаём singleton
    bootstrap, _ = SuperuserBootstrap.objects.get_or_create(id=1)

    superusers = User.objects.filter(is_superuser=True, is_active=True)
    count = superusers.count()

    if count >= 2:
        # уже "устаканено" — считаем setup завершённым
        bootstrap.is_setup_complete = True
        bootstrap.setup_completed_at = __import__("django.utils.timezone",
                                                   fromlist=["timezone"]).now()
        bootstrap.initial_superuser = superusers.first()
        bootstrap.save()

    # Дать существующим superuser'ам роль SUPERVISOR
    for u in superusers:
        RoleAssignment.objects.get_or_create(
            user=u,
            role="supervisor",
            scope_type="global",
            scope_id=0,
            revoked_at__isnull=True,
        )


def backwards(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("access", "0001_initial"),
    ]
    operations = [
        migrations.RunPython(forwards, backwards),
    ]
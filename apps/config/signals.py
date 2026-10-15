from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .models import ConfigProfile, ConfigRevision


@receiver(post_save, sender=ConfigProfile)
def _create_revision(sender, instance: ConfigProfile, created: bool, **kwargs):
    """Создать ревизию при создании и при изменении."""
    if created or not ConfigRevision.objects.filter(
        profile=instance, version=instance.version,
    ).exists():
        ConfigRevision.objects.create(
            profile=instance,
            version=instance.version,
            snapshot=instance.to_snapshot(),
        )
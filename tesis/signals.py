from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import Group
from .models import CustomUser


@receiver(post_save, sender=CustomUser)
def sync_user_role_with_groups(sender, instance, created, **kwargs):
    """Synchronizes the 'role' field with Django Groups."""
    if instance.is_superuser:
        return

    if instance.role:
        role_name = instance.role.lower()
        try:
            group = Group.objects.get(name=role_name)
            instance.groups.set([group])
        except Group.DoesNotExist:
            pass

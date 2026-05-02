# accounts/apps.py
from django.apps import AppConfig
from django.db.models.signals import post_migrate


class TesisConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'tesis'

    def ready(self):
        post_migrate.connect(setup_groups_and_permissions, sender=self)


def setup_groups_and_permissions(sender, **kwargs):
    from django.contrib.auth.models import Group, Permission
    from django.contrib.contenttypes.models import ContentType

    try:
        user_ct = ContentType.objects.get(app_label='tesis', model='customuser')
    except ContentType.DoesNotExist:
        return

    # 1. Define the Groups
    admin_group, _ = Group.objects.get_or_create(name='admin')
    user_group, _ = Group.objects.get_or_create(name='user')

    def get_perms(codenames):
        return Permission.objects.filter(
            content_type=user_ct,
            codename__in=codenames
        )

    admin_perms = [
        "change_user_data",
        "change_admin_data",
        "change_own_data",
        "change_other_data",
    ]

    user_perms = [
        'change_own_data',
        'change_user_data',
    ]

    admin_perms_list = get_perms(admin_perms)
    user_perms_list = get_perms(user_perms)
    admin_group.permissions.set(admin_perms_list)
    user_group.permissions.set(user_perms_list)

    print(f"Sincronizados {admin_perms_list.count()} permisos para Admin y {user_perms_list.count()} permisos para User.")

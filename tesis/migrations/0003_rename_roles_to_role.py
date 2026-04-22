from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('tesis', '0002_alter_customuser_ci'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customuser',
            old_name='roles',
            new_name='role',
        ),
    ]

# Generated by Django 3.2.4 on 2021-08-14 17:24

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('admin_dashboard', '0005_emailsettings'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='EmailSettings',
            new_name='email_settings',
        ),
    ]
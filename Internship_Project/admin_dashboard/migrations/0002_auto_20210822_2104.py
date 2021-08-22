# Generated by Django 3.2.5 on 2021-08-22 15:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('admin_dashboard', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='module',
            old_name='controlller_name',
            new_name='controller_name',
        ),
        migrations.AlterField(
            model_name='module',
            name='module_name',
            field=models.CharField(max_length=1000),
        ),
        migrations.AlterField(
            model_name='myuser',
            name='role',
            field=models.CharField(default='No Role', max_length=500, verbose_name='role'),
        ),
    ]

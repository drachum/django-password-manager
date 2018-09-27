# Generated by Django 2.1.1 on 2018-09-24 21:00

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('password_manager', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='password',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='passwords_encrypted', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='temporarykey',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='temporary_key', serialize=False, to=settings.AUTH_USER_MODEL),
        ),
    ]

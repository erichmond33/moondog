# Generated by Django 5.0.3 on 2024-07-08 00:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("Linkfeed", "0003_alter_alloweddomain_user"),
    ]

    operations = [
        migrations.AddField(
            model_name="comment",
            name="level",
            field=models.IntegerField(default=0),
        ),
    ]

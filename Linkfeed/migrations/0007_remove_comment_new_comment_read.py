# Generated by Django 5.0.3 on 2024-07-13 21:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("Linkfeed", "0006_comment_new"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="comment",
            name="new",
        ),
        migrations.AddField(
            model_name="comment",
            name="read",
            field=models.BooleanField(default=False),
        ),
    ]

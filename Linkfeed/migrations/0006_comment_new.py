# Generated by Django 5.0.3 on 2024-07-13 21:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("Linkfeed", "0005_remove_importedrssfeed_user_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="comment",
            name="new",
            field=models.BooleanField(default=True),
        ),
    ]

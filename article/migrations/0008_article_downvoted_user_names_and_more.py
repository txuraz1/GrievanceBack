# Generated by Django 4.2 on 2023-06-09 08:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('article', '0007_remove_article_downvoted_by_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='article',
            name='downvoted_user_names',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='article',
            name='upvoted_user_names',
            field=models.TextField(blank=True),
        ),
    ]
# Generated by Django 4.2 on 2023-06-09 08:08

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('article', '0008_article_downvoted_user_names_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='article',
            name='downvoted_user_names',
        ),
        migrations.RemoveField(
            model_name='article',
            name='upvoted_user_names',
        ),
        migrations.AlterField(
            model_name='article',
            name='downvoted_by',
            field=models.ManyToManyField(related_name='downvoted_articles', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='article',
            name='upvoted_by',
            field=models.ManyToManyField(related_name='upvoted_articles', to=settings.AUTH_USER_MODEL),
        ),
    ]

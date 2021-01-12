# Generated by Django 3.1.4 on 2021-01-11 10:27

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Hope',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=100, null=True)),
                ('likes', models.PositiveIntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Post',
            fields=[
                ('post_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=30, null=True)),
                ('content', models.TextField()),
                ('author', models.CharField(max_length=50)),
                ('author_id', models.CharField(max_length=100)),
                ('created_dt', models.DateTimeField(auto_now_add=True)),
                ('views', models.PositiveIntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='HopeCard',
            fields=[
                ('card_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('nickname', models.CharField(max_length=15)),
                ('email', models.EmailField(max_length=254)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('content', models.TextField()),
                ('private_opt', models.BooleanField()),
                ('author', models.CharField(max_length=50)),
                ('hope_list', models.ManyToManyField(to='main.Hope')),
            ],
        ),
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('author', models.CharField(max_length=50)),
                ('content', models.TextField(max_length=200)),
                ('post_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.post')),
            ],
        ),
    ]

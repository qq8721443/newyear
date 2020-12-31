from django.db import models

class Post(models.Model):
    title = models.CharField(max_length=30, null=True)
    content = models.TextField()

class Hope(models.Model):
    title = models.CharField(max_length=100, null=True)
    likes = models.PositiveIntegerField(default=0)

class HopeCard(models.Model):
    card_id = models.BigAutoField(primary_key=True)
    nickname = models.CharField(max_length=15)
    email = models.EmailField()
    create_date = models.DateTimeField(auto_now_add=True)
    content = models.TextField()
    private_option = models.BooleanField()
    hopes = models.ManyToManyField(Hope)


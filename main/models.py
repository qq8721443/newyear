from django.db import models

class Hope(models.Model):
    nickname = models.CharField(max_length=15)
    email = models.EmailField()
    create_date = models.DateTimeField(auto_now_add=True)
    content = models.TextField()
    private_option = models.BooleanField()



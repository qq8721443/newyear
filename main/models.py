from django.db import models

class User(models.Model):
    objects = models.Manager()
    kakao_user_id = models.PositiveIntegerField(null=True)
    email = models.EmailField()
    password = models.CharField( max_length=100, null=True )
    nickname = models.CharField(max_length=20)



class Post(models.Model):
    objects = models.Manager()
    post_id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=30, null=True)
    content = models.TextField()
    author = models.CharField(max_length=50)
    author_id = models.CharField(max_length=100)
    created_dt = models.DateTimeField(auto_now_add=True)
    views = models.PositiveIntegerField(default=0)

    # class Meta:
    #     ordering = ['-created_dt']

class Comment(models.Model):
    objects = models.Manager()
    author = models.CharField(max_length=50)
    content = models.TextField(max_length=200)
    post_id = models.ForeignKey(Post, on_delete=models.CASCADE)

class Hope(models.Model):
    objects = models.Manager()
    title = models.CharField(max_length=100, null=True)
    likes = models.PositiveIntegerField(default=0)

class HopeCard(models.Model):
    objects = models.Manager()
    card_id = models.BigAutoField(primary_key=True)
    nickname = models.CharField(max_length=15)
    email = models.EmailField()
    created_date = models.DateTimeField(auto_now_add=True)
    content = models.TextField()
    private_opt = models.BooleanField()
    hope_list = models.ManyToManyField(Hope)
    author = models.CharField(max_length=50)


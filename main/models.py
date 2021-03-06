from django.db import models

class User(models.Model):
    objects = models.Manager()
    kakao_user_id = models.PositiveIntegerField(null=True)
    email = models.EmailField()
    password = models.CharField( max_length=100, null=True )
    nickname = models.CharField(max_length=20)
    describe = models.TextField(max_length=100, default="작성한 소개글이 없습니다.")



class Post(models.Model):
    objects = models.Manager()
    post_id = models.BigAutoField(primary_key=True)
    title = models.CharField(max_length=30, null=True)
    content = models.TextField()
    goal = models.CharField(max_length=100, null=True)
    author = models.CharField(max_length=50)
    author_email = models.CharField(max_length=100)
    claps =  models.ManyToManyField(User, related_name='like_posts', blank=True)
    created_dt = models.DateTimeField(auto_now_add=True)
    is_success = models.BooleanField(default=False)
    is_ongoing = models.BooleanField(default=True)
    is_fail = models.BooleanField(default=False)
    diff_date = models.PositiveIntegerField()

    # class Meta:
    #     ordering = ['-created_dt']

class Comment(models.Model):
    objects = models.Manager()
    author = models.CharField(max_length=50)
    author_email = models.CharField(max_length=100)
    content = models.TextField(max_length=200)
    post_id = models.ForeignKey(Post, on_delete=models.CASCADE)
    created_dt = models.DateTimeField(auto_now_add=True)

# class Hope(models.Model):
#     objects = models.Manager()
#     title = models.CharField(max_length=100, null=True)
#     likes = models.PositiveIntegerField(default=0)

# class HopeCard(models.Model):
#     objects = models.Manager()
#     card_id = models.BigAutoField(primary_key=True)
#     nickname = models.CharField(max_length=15)
#     email = models.EmailField()
#     created_date = models.DateTimeField(auto_now_add=True)
#     content = models.TextField()
#     private_opt = models.BooleanField()
#     hope_list = models.ManyToManyField(Hope)
#     author = models.CharField(max_length=50)


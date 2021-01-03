from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.core import serializers
from .models import HopeCard, Hope, Post, Comment
import json

class PostView(View):
    def get(self, request):
        if Post.objects.exists():
            data = list(Post.objects.values())      #model을 value로 조회하고 list로 감싼다
            return JsonResponse(data, safe=False)   #safe=False 옵션을 추가해 response 전송
        else:
            return JsonResponse({'message':'get post', 'res':"there's no data"})

    def post(self, request):
        data = json.loads(request.body)
        Post(
            title = data['title'],
            content = data['content'],
            author = data['author']
        ).save()
        return JsonResponse({'message':'post post', 'res':data})

    def delete(self, request):
        data = Post.objects.all()
        data.delete()
        return JsonResponse({'message':'delete complete'})

class DetailPost(View):
    def get(self, request, post_id):
        if Post.objects.filter(post_id = post_id).exists():
            data = list(Post.objects.filter(post_id = post_id).values())
            return JsonResponse({'message':'get detail post', 'res':data})
        else:
            return JsonResponse({'message':"there's no data"})

    def put(self, request, post_id):
        # PATCH로 대체 가능할듯?
        return JsonResponse({'message':'put detail post'})

    def patch(self, request, post_id):
        req_data = json.loads(request.body)             # request data 저장
        data = Post.objects.get(post_id = post_id)      # url의 post_id를 통해 모델에서 일치하는 데이터 가져오기 ‼️ 여기서는 filter 대신 get을 사용해야함.
        data.title = req_data['title']                  # title 수정
        data.content = req_data['content']              # content 수정
        data.save()                                     # 저장
        return JsonResponse({'message':'patch detail post', 'success':'true'})

    def delete(self, request, post_id):
        data = Post.objects.get(post_id = post_id)
        data.delete()
        return JsonResponse({'message':'delete detail post', 'success':'true'})

class KakaoLogin(View):
    def get(self, request):
        # 제일 마지막에 하는게 나을듯?
        return JsonResponse({'message':'kakao login'})

class HopeView(View):
    def get(self, request):
        data = list(Hope.objects.all().values())
        return JsonResponse({'message':'get hope', 'res':data})

    def post(self, request):
        req_data = json.loads(request.body)
        Hope(
            title = req_data['title']
        ).save()
        return JsonResponse({'message':'create hope'})
    
class HopeCardView(View):
    def post(self, request):
        req_data = json.loads(request.body)
        HopeCard(
            email = req_data['email'],
            content = req_data['content'],
            author = req_data['author'],
            private_opt = req_data['private_opt']
            # req_data에 있는 hope_list를 저장해야함
        ).save()
        return JsonResponse({'message':'create hopecard'})

class CommentView(View):
    def get(self, request):
        data = list(Comment.objects.all().values())
        return JsonResponse({'message':'get comments', 'res':data})

class DetailComment(View):
    def get(self, request, post_id):
        if Comment.objects.filter(post_id = post_id).exists():
            data = list(Comment.objects.filter(post_id = post_id).values())
            return JsonResponse({'message':'get detail comment', 'res':data})
        else:
            return JsonResponse({'message':"there's no data"})
    
    def post(self, request, post_id):
        req_data = json.loads(request.body)
        Comment(
            content = req_data['content'],
            author = req_data['author'],
            post_id = Post.objects.get(post_id = post_id)
        ).save()
        return JsonResponse({'message':'post comments'})

class DeleteComment(View):
    def delete(self, request, comment_id):
        test_data = Comment.objects.get(id = comment_id)
        test_data.delete()
        return JsonResponse({'message':'delete comment', 'success':'true'})
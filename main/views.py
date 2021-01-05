from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.core import serializers
from .models import HopeCard, Hope, Post, Comment
import json
import requests

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
            # req_data에 있는 hope_list를 저장해야함, m2m field 이해가 필요한듯
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

class KakaoLogin(View):
    def get(self, request):
        # 제일 마지막에 하는게 나을듯?
        # 이 부분은 프론트에서 해야하는듯
        client_id = '20887ce0003dfa62635c435e177fee15'
        redirect_uri = 'http://localhost:8000/main/oauth/'
        url = f'https://kauth.kakao.com/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code'
        return redirect(url)

class Oauth(View):
    def post(self, request):
        # code = request.GET.get('code', None)
        data = json.loads(request.body)
        code = data['code']
        url = 'https://kauth.kakao.com/oauth/token'
        client_id = '20887ce0003dfa62635c435e177fee15'
        redirect_uri = 'http://localhost:3000/oauth'
        headers = { 'Content-type':'application/x-www-form-urlencoded;charset=utf-8' }
        params = {
            'grant_type':'authorization_code',
            'client_id':client_id,
            'redirect_uri':redirect_uri,
            'code':code
        }
        res = requests.post(url, headers=headers, params=params)
        # print(res.json()['access_token'])
        return JsonResponse({'message':'redirect uri', 'res':res.json()})
        # return redirect('http://localhost:3000')

class CheckToken(View):
    def post(self, request):
        data = json.loads(request.body)
        url = 'https://kapi.kakao.com/v1/user/access_token_info'
        headers = {
            'Authorization': f'Bearer {data["access_token"]}',
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8'
        }
        res = requests.get(url, headers=headers)
        return JsonResponse(res.json())

class RefreshToken(View):
    def post(self, request):
        data = json.loads(request.body)
        url = 'https://kauth.kakao.com/oauth/token'
        client_id = '20887ce0003dfa62635c435e177fee15'
        params = {
            'grant_type':'refresh_token',
            'client_id':client_id,
            'refresh_token':data['refresh_token']
        }
        res = requests.post(url, params = params)
        return JsonResponse(res.json())

class UserInfo(View):
    def post(self, request):
        data = json.loads(request.body)
        url = 'https://kapi.kakao.com/v2/user/me'
        headers = {
            'Authorization':f'Bearer {data["access_token"]}',
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8'
        }
        res = requests.post(url, headers=headers)
        print(res.json())
        return JsonResponse(res.json())

class Oauth2(View):
    def get(self, request):

        return JsonResponse({'message':'oauth 2'})

class Logout(View):
    def get(self, request):

        return JsonResponse({'message':'logout'})
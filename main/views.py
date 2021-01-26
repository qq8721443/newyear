from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.core import serializers
from .models import Post, Comment, User
import json
import requests
import bcrypt
import jwt
import math
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.middleware.csrf import get_token
from datetime import datetime, timedelta
from .utils import SECRET_KEY_ACCESS, SECRET_KEY_REFRESH, ALGORITHM

class SignUp(View):
    def post(self, request):
        data = json.loads(request.body)

        if data['exist_check']:
            if User.objects.filter(kakao_user_id = data['kakao_user_id']).exists():
                ins = User.objects.get(kakao_user_id = data['kakao_user_id'])
                access_token = jwt.encode({'email':ins.email}, SECRET_KEY_ACCESS, algorithm=ALGORITHM)
                refresh_token = jwt.encode({'email':ins.email, 'exp':datetime.utcnow() + timedelta(weeks=4)}, SECRET_KEY_REFRESH, algorithm=ALGORITHM)
                return JsonResponse({'message':'이미 등록 완료', 'already':True, 'nickname':ins.nickname, 'email':ins.email, 'access_token':access_token, 'refresh_token':refresh_token})
            else:
                return JsonResponse({'message':'카카오 로그인 진행', 'already':False, 'id':data['kakao_user_id']})
        else:
            if data['kakao_login']:
                if User.objects.filter(email = data['email']).exists():
                    return JsonResponse({'message':'이미 등록된 이메일 있음', 'success':False})
                else:
                    User(
                        email = data['email'],
                        nickname = data['nickname'],
                        kakao_user_id = data['kakao_user_id']
                    ).save()
                    ins = User.objects.get(kakao_user_id = data['kakao_user_id'])
                    access_token = jwt.encode({'email':ins.email, 'exp':datetime.utcnow() + timedelta(days=1)}, SECRET_KEY_ACCESS, algorithm=ALGORITHM)
                    refresh_token = jwt.encode({'email':ins.email, 'exp':datetime.utcnow() + timedelta(weeks=4)}, SECRET_KEY_REFRESH, algorithm=ALGORITHM)
                    return JsonResponse({'message':'kakao login success', 'access_token':access_token, 'nickname':ins.nickname, 'email':ins.email, 'refresh_token':refresh_token, 'success':True})
                # 카카오 로그인은 따로 로그인 과정이 없기 때문에 여기서 jwt 반환

            else :
                if User.objects.filter(email = data['email']).exists():
                    return JsonResponse({'message':'이메일로 가입한 계정 있음', 'success':False})
                else :
                    password = data['password']
                    encoded_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    print(encoded_password)

                    User(
                        email = data['email'],
                        password = encoded_password.decode(),
                        nickname = data['nickname']
                    ).save()
                    return JsonResponse({'message':'normal sign up success', 'success':True})

class SignIn(View):
    def post(self, request):
        data = json.loads(request.body)
        
        if User.objects.filter(email = data['email']).exists():
            instance = User.objects.get(email = data['email'])
            if bcrypt.checkpw(data['password'].encode('utf-8'), instance.password.encode('utf-8')):
                # jwt 토큰 반환
                access_token = jwt.encode({'email':data['email'], 'exp':datetime.utcnow() + timedelta(days=1)}, SECRET_KEY_ACCESS, algorithm=ALGORITHM)
                refresh_token = jwt.encode({'email':data['email'], 'exp':datetime.utcnow() + timedelta(weeks=4)}, SECRET_KEY_REFRESH, algorithm=ALGORITHM)
                print(access_token, refresh_token)
                return JsonResponse({'message':'로그인 성공', 'email':instance.email, 'nickname':instance.nickname, 'access_token':access_token, 'refresh_token':refresh_token, 'success':True})
            else:
                return JsonResponse({'message':'비밀번호가 틀립니다'})
        else:
            return JsonResponse({'message':'계정 존재하지 않음'})

class PostView(View):
    def get(self, request):
        if Post.objects.exists():
            data = list(Post.objects.values().order_by('-created_dt'))      #model을 value로 조회하고 list로 감싼다
            return JsonResponse(data, safe=False)   #safe=False 옵션을 추가해 response 전송
        else:
            return JsonResponse({'message':'get post', 'res':"there's no data"})

    def post(self, request):
        data = json.loads(request.body)
        Post(
            title = data['title'],
            content = data['content'],
            author = data['author'],
            author_email = data['author_email'],
            diff_date= data['date_difference']
        ).save()
        
        test = list(Post.objects.filter(title = data['title'], content = data['content'], author = data['author']).values())
        
        return JsonResponse({'message':'post post', 'res':test})

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

class UserCheck(View):
    def post(self, request):
        data = json.loads(request.body)
        access_token = data['access_token']
        post_id = data['post_id']
        try:
            decode = jwt.decode(access_token, SECRET_KEY_ACCESS, algorithms=ALGORITHM)
            if Post.objects.get(post_id = post_id).author_email == decode['email']:
                return JsonResponse({'is_author':True})
            else:
                return JsonResponse({'is_author':False})
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error':'Signature has expired'})

class CallNowPost(View):
    def get(self, request):
        try:
            receive = request.headers
            access_token = receive['access-token']
            jwt_payload = jwt.decode(access_token, SECRET_KEY_ACCESS, algorithms=ALGORITHM)
            author_email = jwt_payload['email']
            data = Post.objects.filter(author_email=author_email).order_by('-created_dt').first()
            all_count = Post.objects.filter(author_email=author_email).count()
            success_count = Post.objects.filter(author_email=author_email, is_success=True).count()
            ongoing_count = Post.objects.filter(author_email=author_email, is_ongoing=True).count()
            success_rate = round(float(success_count / all_count) * 100)
            claps = data.claps.count()
            print(data.diff_date)
            remain_time = (data.created_dt + timedelta(days=data.diff_date)) - datetime.now()
            remain_days = remain_time.days
            remain_hours = math.floor((remain_time - timedelta(days=remain_days)).seconds /3600)
            remain_minutes = math.floor((remain_time - timedelta(days = remain_days) - timedelta(hours = remain_hours)).seconds / 60)
            remain_rate = round(((datetime.now() - data.created_dt) / remain_time) * 100)
            return JsonResponse({'nowposttitle':data.title, 'claps':claps, 'count':{'all':all_count, 'success':success_count, 'ongoing':ongoing_count}, 'rate':{'success':success_rate, 'remain':remain_rate}, 'remain':{'days':remain_days, 'hours':remain_hours, 'minutes':remain_minutes}})
        except jwt.ExpiredSignatureError:
            return JsonResponse({'message':'Signature has expired'})
        except AttributeError:
            return JsonResponse({'message':"attributeError"})
        except ZeroDivisionError:
            return JsonResponse({'nowposttitle':'작성한 목표가 없습니다.', 'claps':0, 'count':{'all':0, 'success':0, 'ongoing':0}, 'rate':{'success':0, 'remain':0}, 'remain':{'days':0, 'hours':0, 'minutes':0}})

class ChangeSuccess(View):
    def patch(self, request, post_id):
        data = Post.objects.get(post_id = post_id)
        data.is_ongoing = False
        data.is_success = True
        data.save()
        return JsonResponse({'message':'state change to success'})
        
class ChangeFail(View):
    def patch(self, request, post_id):
        data = Post.objects.get(post_id = post_id)
        data.is_ongoing = False
        data.is_fail = True
        data.save()
        return JsonResponse({'message':'state change to fail'})

class PostLike(View):
    def post(self, request, post_id):
        headers = request.headers
        access_token = headers['access-token']
        email = jwt.decode(access_token, SECRET_KEY_ACCESS, algorithms=ALGORITHM)['email']
        post = Post.objects.get(post_id=post_id)
        if post.claps.filter(email=email).exists():
            print(email)
            post.claps.remove(User.objects.get(email=email))
        else:
            post.claps.add(User.objects.get(email=email))
        return JsonResponse({'message':'like test'})

class MyLike(View):
    def post(self, request):
        headers = request.headers
        access_token = headers['access-token']
        email = jwt.decode(access_token, SECRET_KEY_ACCESS, algorithms=ALGORITHM)['email']
        posts = Post.objects.filter(claps=User.objects.get(email=email))
        mlp_count = posts.count()
        return JsonResponse({'data':mlp_count})

class GenerateCSRF(View):
    def get(self, request):
        return JsonResponse({'csrfToken':get_token(request)})

class CsrfTest(View):
    def post(self, request):
        return JsonResponse({'message':'CSRF success!!'})

class Oauth2(View):
    def get(self, request):

        return JsonResponse({'message':'oauth 2'})

class Logout(View):
    def get(self, request):

        return JsonResponse({'message':'logout'})


# def csrf(request):
#     return JsonResponse({'csrfToken': get_token(request)})

# def ping(request):
#     return JsonResponse({'result': 'OK'})
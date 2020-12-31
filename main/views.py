from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views import View
from .models import HopeCard, Hope, Post
import json


class SaveCard(View):  
    def post(self, request):  
        req = json.loads(request.body)
        nickname = req['nickname']
        email = req['email']
        content = req['content']
        private_option = req['po']

        #새로운 목표가 있다면 목표를 hope DB에 저장한 후 hopecard를 저장
        

        hopecard = HopeCard(
            nickname = nickname,
            email = email,
            content = content,
            private_option = private_option
        )
        hopecard.save()
        
        return JsonResponse({'success':'true'})

class SaveHope(View):
    def post(self, request):
        req = json.loads(request.body)
        title = req['title']

        temp = Hope(
            title = title
        )
        temp.save()

        return JsonResponse({'message':'success', 'request':req})
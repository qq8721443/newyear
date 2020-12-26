from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views import View
from .models import Hope

class SendView(View):  
    def get(self, request):  
        nickname = 'tompson'
        email = 'qq8721443@naver.com'
        content = ' 이런걸 했으면 좋겠네요'
        private_option = False  

        hope = Hope(
            nickname = nickname,
            email = email,
            content = content,
            private_option = private_option
        )
        hope.save()
        
        return JsonResponse({'success':'true'})

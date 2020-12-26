from django.urls import path
from .views import SendView

urlpatterns = [
    path('',  SendView.as_view()),
]

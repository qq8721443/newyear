from django.urls import path
from .views import SaveCard, SaveHope

urlpatterns = [
    path('savecard/',  SaveCard.as_view()),
    path('savehope/', SaveHope.as_view()),
]

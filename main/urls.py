from django.urls import path
from .views import PostView, DetailPost, KakaoLogin, HopeView, HopeCardView, CommentView, DetailComment, DeleteComment

urlpatterns = [
    path('posts/', PostView.as_view()),
    path('posts/<int:post_id>/', DetailPost.as_view()),
    path('sign_in/', KakaoLogin.as_view()),
    path('hopes/', HopeView.as_view()),
    path('hopecard/', HopeCardView.as_view()),
    path('comments/all/', CommentView.as_view()),
    path('comments/<int:post_id>/', DetailComment.as_view()),
    path('comments/delete/<int:comment_id>/', DeleteComment.as_view())
]

from django.urls import path
from .views import PostView, DetailPost, KakaoLogin, HopeView, HopeCardView, CommentView, DetailComment, DeleteComment, Oauth, Oauth2, Logout, CheckToken, RefreshToken, UserInfo, CsrfTest, GenerateCSRF

urlpatterns = [
    path('posts/', PostView.as_view()),
    path('posts/<int:post_id>/', DetailPost.as_view()),
    path('sign_in/', KakaoLogin.as_view()),
    path('hopes/', HopeView.as_view()),
    path('hopecard/', HopeCardView.as_view()),
    path('comments/all/', CommentView.as_view()),
    path('comments/<int:post_id>/', DetailComment.as_view()),
    path('comments/delete/<int:comment_id>/', DeleteComment.as_view()),
    path('oauth/', Oauth.as_view()),     # redirect uri
    path('oauth2/', Oauth2.as_view()),
    path('logout/', Logout.as_view()),
    path('token_check/', CheckToken.as_view()),
    path('refresh_token/', RefreshToken.as_view()),
    path('user_info/', UserInfo.as_view()),
    path('csrf_test/', CsrfTest.as_view()),
    path('get_csrf/', GenerateCSRF.as_view()),
    # path('csrf/', csrf),
    # path('ping/', ping)
]

from django.urls import path
from .views import PostView, DetailPost, CommentView, DetailComment, DeleteComment, Oauth, Oauth2, Logout, KakaoCheckToken, KakaoRefreshToken, KakaoUserInfo, CsrfTest, GenerateCSRF, SignUp, SignIn, UserCheck, CallNowPost, ChangeSuccess, ChangeFail, PostLike, MyLike, ExpiredCheck, HotPost, CallUserInfo, ExtraPost, OrmTest, ChangeUser

urlpatterns = [
    path('posts/', PostView.as_view()),
    path('posts/extra/<int:page_num>/', ExtraPost.as_view()),
    path('posts/<int:post_id>/', DetailPost.as_view()),
    path('posts/hot/', HotPost.as_view()),
    path('signin/', SignIn.as_view()),
    path('comments/all/', CommentView.as_view()),
    path('comments/<int:post_id>/', DetailComment.as_view()),
    path('comments/delete/<int:comment_id>/', DeleteComment.as_view()),
    path('oauth/', Oauth.as_view()),     # redirect uri
    path('oauth2/', Oauth2.as_view()),
    path('logout/', Logout.as_view()),
    path('token_check/', KakaoCheckToken.as_view()),
    path('refresh_token/', KakaoRefreshToken.as_view()),
    path('user_info/', KakaoUserInfo.as_view()),
    path('csrf_test/', CsrfTest.as_view()),
    path('get_csrf/', GenerateCSRF.as_view()),
    path('signup/', SignUp.as_view()),
    path('user_check/', UserCheck.as_view()),
    path('test/', CallNowPost.as_view()),
    path('change_success/<int:post_id>/', ChangeSuccess.as_view()),
    path('change_fail/<int:post_id>/', ChangeFail.as_view()),
    path('like_post/<int:post_id>/', PostLike.as_view()),
    path('my_like/', MyLike.as_view()),
    path('expired_check/', ExpiredCheck.as_view()),
    path('call_user_info/', CallUserInfo.as_view()),
    path('orm_test/', OrmTest.as_view()),
    path('change_user/', ChangeUser.as_view())
    # path('csrf/', csrf),
    # path('ping/', ping)
]

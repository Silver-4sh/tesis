from django.urls import path

from . import views
from .views import UserCreationView, UserLoginView, LogoutView, VerifyAccountView, TestView

urlpatterns = [
    path('', views.HomeView.as_view(), name='home'),
    path('user-creation', UserCreationView.as_view(), name='user-creation'),
    path('login', UserLoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),

    path('profile/<str:mode>/<int:user_id>/', views.ProfileView.as_view(), name='profile'),

    path('test', TestView.as_view(), name='test'),


    path('activate/<uidb64>/<token>', VerifyAccountView.as_view(), name='verify_account'),

    path('password-reset/', views.UserPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', views.UserPasswordResetDoneView.as_view(), name='password_reset_done'),

    path('reset/<uidb64>/<token>/', views.UserPasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    path('reset/done/', views.UserPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]

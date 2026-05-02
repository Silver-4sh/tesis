from django.urls import path

from . import views
from .views import UserCreationView, UserLoginView, LogoutView, VerifyAccountView, TestView, ResendActivationView

urlpatterns = [

    path('auth-user-creation', UserCreationView.as_view(), name='auth-user-creation'),
    path('auth-login', UserLoginView.as_view(), name='auth-login'),
    path('auth-logout', LogoutView.as_view(), name='auth-logout'),

    path('verify-account/<uidb64>/<token>', VerifyAccountView.as_view(), name='verify-account'),
    path('verify-resend/<uidb64_pk>/', ResendActivationView.as_view(), name='verify-resend'),

    path('pass-reset/', views.UserPasswordResetView.as_view(), name='pass-reset'),
    path('pass-reset/done/', views.UserPasswordResetDoneView.as_view(), name='pass-reset-done'),
    path('pass-reset/confirm/<uidb64>/<token>/', views.UserPasswordResetConfirmView.as_view(), name='pass-reset-confirm'),
    path('pass-reset/complete/', views.UserPasswordResetCompleteView.as_view(), name='pass-reset-complete'),

    path('contact-admin/', views.SendEmailView.as_view(), name='contact-admin'),

    path('profile/', views.ProfileView.as_view(), name='profile'),

    path('test', TestView.as_view(), name='test'),
    path('', views.HomeView.as_view(), name='home'),
]

from django.urls import path

from . import views
from .views import UserCreationView, UserLoginView, LogoutView, VerificationView, TestView, VerificationResendView, VerificationRemoveView

urlpatterns = [

    path('auth-user-creation', UserCreationView.as_view(), name='auth-user-creation'),
    path('auth-login', UserLoginView.as_view(), name='auth-login'),
    path('auth-logout', LogoutView.as_view(), name='auth-logout'),

    path('ver-account/<uidb64>/<token>', VerificationView.as_view(), name='ver-account'),
    path('ver-resend/<uidb64_pk>/', VerificationResendView.as_view(), name='ver-resend'),
    path('ver-remove/<uidb64>/<token>/', VerificationRemoveView.as_view(), name='ver-remove'),

    path('pass-reset/', views.UserPasswordResetView.as_view(), name='pass-reset'),
    path('pass-reset/done/', views.UserPasswordResetDoneView.as_view(), name='pass-reset-done'),
    path('pass-reset/confirm/<uidb64>/<token>/', views.UserPasswordResetConfirmView.as_view(), name='pass-reset-confirm'),
    path('pass-reset/complete/', views.UserPasswordResetCompleteView.as_view(), name='pass-reset-complete'),

    path('send-email/', views.SendEmailView.as_view(), name='send-email'),

    path('profile/', views.ProfileView.as_view(), name='profile'),

    path('test', TestView.as_view(), name='test'),
    path('', views.HomeView.as_view(), name='home'),
]

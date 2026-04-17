from django.urls import path

from . import views
from .views import UserCreationView, UserLoginView, LogoutView, VerifyAccountView

urlpatterns = [
    path('', views.HomeView.as_view(), name='home'),
    path('user-creation', UserCreationView.as_view(), name='user-creation'),
    path('login', UserLoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),

    path('activate/<uidb64>/<token>', VerifyAccountView.as_view(), name='verify_account'),
]

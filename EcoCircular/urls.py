"""
URL configuration for EcoCircular project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name = 'home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name = 'home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

from tesis.views import Custom404View, Custom400View, Custom403View, custom_500_handler

handler400 = Custom400View.as_view()
handler403 = Custom403View.as_view()
handler404 = Custom404View.as_view()
handler500 = 'tesis.views.custom_500_handler'


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('tesis.urls')),
]

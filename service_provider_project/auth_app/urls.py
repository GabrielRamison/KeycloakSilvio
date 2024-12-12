# service_provider/auth_app/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.HomeView.as_view(), name='home'),
    path('userinfo/', views.UserInfoView.as_view(), name='userinfo'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('register/', views.LoginView.as_view(), name='register'),
    path('callback/', views.LoginCallbackView.as_view(), name='callback'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
]
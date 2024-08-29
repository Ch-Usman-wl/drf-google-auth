from django.urls import path, include

from . import views
urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('accounts/login/', views.login, name='login'),
    path('test/', views.test, name='test'),
    path('auth/google/login/', views.google_login, name='google_login'),
    path('auth/complete/google/', views.google_callback, name='google_callback'),
    #path('auth/convert-to-jwt/', views.convert_token_to_jwt, name='convert_token_to_jwt'),
    path('convert/', views.MyView.as_view() , name='convert'),
    path('logout/', views.google_logout, name='google_logout'),
]
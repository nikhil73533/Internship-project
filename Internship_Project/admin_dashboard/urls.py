#<============= For reset password ===== >
from django.contrib import admin
from django.contrib import auth 
from django.urls import path
from django.contrib.auth import views as auth_views  
#======== end of code======================

urlpatterns = [
    path('admin/', admin.site.urls()),
    path('reset_password',auth_views.PasswordResetView.as_view()),
    path('reset_password_sent',auth_views.PasswordResetDoneView.as_view()),
    path('reset_password_sent',auth_views.PasswordResetDoneView.as_view()),
    path('reset/<uidb64>/<token>/',auth_views.PasswordResetConfirmView.as_view()),
    path('reset_password_complete/',auth_views.PasswordResetCompleteView.as_view()),

]

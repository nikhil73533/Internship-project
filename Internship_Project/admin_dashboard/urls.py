from django.contrib import admin
from django.urls import path
#<==== Importing function from views of admin dashboard =======>
from .views import Login
#<-======= end of code===>
#<===== Reset Password========>
from django.contrib.auth.views import PasswordResetView,PasswordResetDoneView,PasswordResetConfirmView,PasswordResetCompleteView
#<===============end of code ========>

urlpatterns = [
    #<=========login page Urls============>
    path('',Login,name = "Login"),
    #<=======end of code ==============>

    #<=========Password Reset Urls============>

    path('reset_password/',PasswordResetView.as_view(template_name = "reset_password/forgot_pass.html"),name = 'reset_password'),
    path('reset_password_sent/',PasswordResetDoneView.as_view(template_name = ""), name = "password_reset_done"),
    path('reset/<uidb64>/<token>', PasswordResetConfirmView.as_view(template_name = ""), name = "password_reset_confirm"),
    path('reset_password_complete/',PasswordResetCompleteView.as_view(template_name = ""), name = "password_reset_complete"),

   # <============ END OF CODE===============================>

]


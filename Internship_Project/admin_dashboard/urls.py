from django.contrib import admin
from django.urls import path

#<==== Importing function from views of admin dashboard =======>
from .views import Login, Register, Verification, Login_View,DashBoard,LogOut,Crud

#<===== Reset Password========>
from django.contrib.auth.views import PasswordResetView,PasswordResetDoneView,PasswordResetConfirmView,PasswordResetCompleteView

urlpatterns = [

    path('activate/<uidb64>/<token>', Verification.as_view(), name = "activate"),
    path('login', Login_View.as_view(), name = "login"),

    #<======= DashBoard page url =========>
    path('Dashboard',DashBoard,name = "DashBoard"),

     #<======= Crud part 3 page url =========>
    path('Crud',Crud,name = "Crud"),

    #<=========login page Urls============>
    path('', Login, name = "Login"),

     #<=========login page Urls============>
    path('Logout', LogOut, name = "LogOut"),

    #<=========Register page Urls============>
    path('Register', Register, name = "Register"),
   
    #<=========Password Reset Urls============>
    path('reset_password/',PasswordResetView.as_view(template_name = "reset_password/forgot_pass.html"),name = 'reset_password'),
    path('reset_password_sent/',PasswordResetDoneView.as_view(template_name = "reset_password/alert_message.html"), name = "password_reset_done"),
    path('reset/<uidb64>/<token>', PasswordResetConfirmView.as_view(template_name = "reset_password/new_pass.html"), name = "password_reset_confirm"),
    path('reset_password_complete/',PasswordResetCompleteView.as_view(template_name = "reset_password/pass_confirm.html"), name = "password_reset_complete"),

]


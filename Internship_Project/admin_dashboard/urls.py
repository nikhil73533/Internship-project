from django.contrib import admin
from django.urls import path

#<==== Importing function from views of admin dashboard =======>
<<<<<<< HEAD
from .views import DashBoardThree, Login, Register, Verification, Login_View,DashBoard,LogOut,Crud,DashBoardTwo,DashBoardThree,Addadmin,Adminlist,view_profile,change_password
=======
from .views import DashBoardThree, Login, Register, Verification, Login_View,DashBoard,LogOut,DashBoardTwo,DashBoardThree,CrudExtension,CrudGenerator,CrudList

>>>>>>> 59679b3cb04a4f3c9d080b05835c5efdde131c9e

#<===== Reset Password========>
from django.contrib.auth.views import PasswordResetView,PasswordResetDoneView,PasswordResetConfirmView,PasswordResetCompleteView

urlpatterns = [

    path('activate/<uidb64>/<token>', Verification.as_view(), name = "activate"),
    path('login', Login_View.as_view(), name = "login"),

    #<======= DashBoard one page url =========>
    path('Dashboard',DashBoard,name = "DashBoard"),

     #<======= DashBoard two page url =========>
    path('DashboardTwo',DashBoardTwo,name = "DashBoardTwo"),

     #<======= DashBoard three page url =========>
    path('DashboardThree',DashBoardThree,name = "DashBoardThree"),


    #<======= Crud part 1 page url =========>
    path('Crudlist',CrudList,name = "CrudList"),
    
    #<======= Crud part 2 page url =========>
    path('CrudGenerator',CrudGenerator,name = "CrudGenerator"),
    
    #<======= Crud part 3 page url =========>
    path('CrudExtension',CrudExtension,name = "CrudExtension"),

     #<======= Add Admin page url =========>
    path('Addadmin',Addadmin,name = "Addadmin"),

     #<======= Admin list page url =========>
    path('Adminlist',Adminlist,name = "Adminlist"),

     #<======= View Profile page url =========>
    path('view_profile',view_profile,name = "view_profile"),

     #<======= Change Password page url =========>
    path('change_password',change_password,name = "change_password"),

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


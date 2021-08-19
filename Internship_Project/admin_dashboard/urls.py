from django.contrib import admin
from django.urls import path
from . import views

#<==== Importing function from views of admin dashboard =======>
from .views import Verification, Login_View, PasswordsChangesView

#<===== Reset Password========>
from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView
from django.contrib.auth.views import PasswordResetCompleteView, PasswordChangeView

urlpatterns = [

  path('activate/<uidb64>/<token>', Verification.as_view(), name = "activate"),
  path('login', Login_View.as_view(), name = "login"),

  #<======= DashBoard one page url =========>
  path('Dashboard', views.DashBoard, name = "DashBoard"),

  #<======= DashBoard two page url =========>
  path('DashboardTwo', views.DashBoardTwo, name = "DashBoardTwo"),

  #<======= DashBoard three page url =========>
  path('DashboardThree', views.DashBoardThree, name = "DashBoardThree"),

  #<======= rolesandpermission  page url =========>
  path('RolePermission/<int:module_id>', views.RolePermission, name = "RolePermission"),

  #<======= Edit new role page url =========>
  path('edit_new_role/<int:module_id>/', views.edit_new_role, name = "edit_new_role"),

  #<======= Edit new role page url =========>
  path('delete_role/<int:module_id>/', views.delete_role, name = "delete_role"),

  #<=======  change password  page url =========>
  path('password/', PasswordsChangesView.as_view(template_name = "profile/change_password.html")),

  #<=======  Edit Addmin list value page url =========>
  path('EditAdminListValue', views.EditAdminListValue, name = "EditAdminListValue"),

  #<======= Filter viewo of admin list page url =========>
  path('filterAdminList', views.filterAdminList, name = "filterAdminList"),

  #<=======  Edit Addmin  value page url =========>
  path('admin_test', views.admintest, name = "admintest"),

  #<=======  Edit Addmin  value page url =========>
  path('edit_admin_list/<int:user_id>/', views.EditAdminList, name = "EditAdminList"),

  #<=======  Delete Admin value page url =========>
  path('delete_admin/<int:user_id>/', views.delete_admin, name = "delete_admin"),    

  #<======= Crud part 1 page url =========>
  path('Crudlist/<str:table>', views.CrudList, name = "CrudList"),
  
  #<======= Crud part 2 page url =========>
  path('CrudGenerator', views.CrudGenerator, name = "CrudGenerator"),
  
  #<======= Crud part 3 page url =========>
  path('CrudExtension', views.CrudExtension, name = "CrudExtension"),

  #<======= Add Admin page url =========>
  path('Addadmin', views.Addadmin, name = "Addadmin"),

  #<======= View Profile page url =========>
  path('view_profile', views.view_profile, name = "view_profile"),

  #<======= Module Settings page url =========>
  path('module_setting', views.module_setting, name = "module_setting"),

  #<======= General Settings page url =========>
  path('general_settings', views.general_settings, name = "general_settings"),

  #<======= Email Settings page url =========>
  path('email_settings', views.EmailSettings, name = "EmailSettings"),
  
  #<======= google reCAPTCHA page url =========>
  path('reCAPTCHA', views.reCAPTCHA, name = "reCAPTCHA"),

  #<======= Admin Roles and permissions page url =========>
  path('admin_roles_and_permission', views.admin_roles_and_permission, name = "admin_roles_and_permission"),

  #<======= Add_new_role page url =========>
  path('add_new_role', views.add_new_role, name = "add_new_role"),

  #<=========login page Urls============>
  path('', views.Login, name = "Login"),

  #<=========login page Urls============>
  path('Logout', views.LogOut, name = "LogOut"),

  #<=========Register page Urls============>
  path('Register', views.Register, name = "Register"),

  #<=========Password Reset Urls============>
  path('reset_password/',PasswordResetView.as_view(template_name = "reset_password/forgot_pass.html"),name = 'reset_password'),
  path('reset_password_sent/',PasswordResetDoneView.as_view(template_name = "reset_password/alert_message.html"), name = "password_reset_done"),
  path('reset/<uidb64>/<token>', PasswordResetConfirmView.as_view(template_name = "reset_password/new_pass.html"), name = "password_reset_confirm"),
  path('reset_password_complete/',PasswordResetCompleteView.as_view(template_name = "reset_password/pass_confirm.html"), name = "password_reset_complete"),

  #<=======  calander  page url =========>
  path('calander', views.calendar, name = "calendar"),

  path('create_table/<str:table>', views.create_table, name = "create_table"),

  path('drop_table/<str:table>', views.drop_table, name = "drop_table"),

  path('delete_crud/<str:table>', views.delete_crud, name = "delete_crud"),

  path('delete_all/<str:table>', views.delete_all, name = "delete_all"),

  path('delete_row/<str:table>/<int:row_id>', views.delete_row, name = "delete_row"),

  path('insert_record/<str:table>', views.insert_record, name = "insert_record"),

  path('edit_record/<str:table>/<int:row_id>', views.edit_record, name = "edit_record"),

  path('edit_crud/<str:table>', views.edit_crud, name = "edit_crud"),

  path('save_changes/<str:table>', views.save_changes, name = "save_changes"),

  path('log', views.log, name = "log"),

  path('save_permissions/<int:module_id>', views.save_permissions, name = "save_permissions")

]


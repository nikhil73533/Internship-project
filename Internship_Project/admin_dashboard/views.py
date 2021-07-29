from django.contrib.auth import models
from django.forms import fields
from django import forms
from django.http import request
from django.contrib.auth import get_user_model
from django.shortcuts import render,redirect
from django.contrib.auth.models import User,auth
from django.contrib import messages
from django.core.mail import EmailMessage, message
from django.urls.base import reverse_lazy
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
# from .models import Profile
from django.urls import reverse
from django.views import View
from .utils import token_generator
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import PasswordChangeView
from django.contrib.auth.forms import PasswordChangeForm
from itertools import zip_longest
import csv
from csv import reader
import pandas as pd
from pathlib import Path
import sqlite3
import json

# User movel initialization 
User = get_user_model()
# <----------------------------------- Dash Board Area for creating views --------------->
# Dashboard 1 view for home page
@login_required(login_url='/') 
def DashBoard(request):
    user = User.objects.get(id = request.user.id)
    count =  User.objects.all().count()
    return render(request,'admin_dashboard/DashBoard_1.html',{'user':user,"count":count})

# DashBoard 2 view in  home page
@login_required(login_url='/') 
def DashBoardTwo(request):
    user = User.objects.get(id = request.user.id)
    return render(request,'admin_dashboard/DashBoard_2.html',{'user':user})

# DashBoard 3 view in  home page
@login_required(login_url='/') 
def DashBoardThree(request):
    user = User.objects.get(id = request.user.id)
    return render(request,'admin_dashboard/DashBoard_3.html',{'user':user})


# DashBoard calander 
@login_required(login_url='/') 
def calander(request):
    return render(request,'admin_dashboard/pages/calendar.html')
# <------------------------------------ End of Area------------------------------>


def LogOut(request):
    auth.logout(request)
    return redirect('/')

# Login view for login page
def Login(request):
    if(request.method=='POST'):
        Password = request.POST['password']
        Username =  request.POST['username']
        user = auth.authenticate(username=Username, password=Password)
        
        if(user is not None and user.is_active):
            auth.login(request, user)
            return redirect('DashBoard')

        else:
            messages.error(request,'Login Failed! ')
            return render(request,'accounts/login.html')
    else:
        return render(request,'accounts/login.html')

# Register view  for register page
def Register(request):
    if(request.method == 'POST'):
        First_Name = request.POST['first_name']
        Last_Name = request.POST['last_name']
        Username = request.POST['user_name']
        email = request.POST['email_address']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
     
        
        if(password==confirm_password):
            if(User.objects.filter(email=email).exists()):
                messages.error(request,'Email Taken')
                return render(request,'accounts/Register.html')

            elif(User.objects.filter(username=Username).exists()):
                messages.error(request,'Username Taken')
                return render(request,'accounts/Register.html')
            else:
                if(password_validate(request,password)):
                    user = User.objects.create_user(first_name = First_Name,last_name = Last_Name, username = Username, email = email, password = password)
                    user.is_active = False
                    user.save()
                    
                    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                    domain = get_current_site(request).domain
                    link = reverse('activate', kwargs = {'uidb64' : uidb64, 'token' : token_generator.make_token(user)})
                    activate_url = 'http://' + domain + link

                    email = EmailMessage(
                        'Account Activation',
                        'Hello ' + Username + ' you can use the following link to activate your account.\n\n' + activate_url,
                        'from@example.com',
                        [email],
                    )
                    email.send(fail_silently = False)

                    messages.success(request,'Account activation mail has been sent')
                    return render(request,"accounts/Register.html")
                else:
                     # return templage to dom using render function
                    return render(request,"accounts/Register.html")
        else:
            messages.error(request,'Password Does Not Match')
            return redirect('Register')
    else:
        # return templage to dom using render function
        return render(request,"accounts/Register.html")

# static function for password validitation
def password_validate(request,password):
    SpecialSymbol =['$', '@', '#', '%'] 
    val = True
      
    if len(password) < 8:
        val = False 
        return messages.error(request,"Password length should be at least 8")
       
    if len(password) > 20: 
        messages.error(request,"Password length should not be greater than 20")
        val = False 
        return  val  
          
    if not any(char.isdigit() for char in password): 
        val = False 
        messages.error(request,"Password should have at least one numeral")
        return val
          
    if not any(char.isupper() for char in password): 
        val = False 
        messages.error(request,"Password should have at least one uppercase letter")
        return val
          
    if not any(char.islower() for char in password): 
        val = False 
        messages.error(request,"Password should have at least one lowercase letter")
        return val
          
    if not any(char in SpecialSymbol for char in password): 
        val = False 
        messages.error(request,"Password should have at least one special character")
        return val

    if val: 
        return val

class Verification(View):
    def get(self, request, uidb64, token):

        try :
            id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk = id)

            user.is_active = True
            user.save()

            if not Token_Generator.check_token(user, token):
                return redirect('Login' + '?message=' + 'User already has an active account')

            if user.is_active:
                return redirect('Login')

            messages.success(request, 'Account activated successfully')
            return render(request, 'accounts/login.html')

        except Exception as e:
            pass

        return redirect('Login')

class Login_View(View):
    def get(self, request):
        return render(request, 'accounts/login.html')

# Crud function 
@login_required(login_url='/') 
def CrudList(request):
    return render(request, "admin_dashboard/CRUD/crud1.html")

# Crud function
@login_required(login_url='/')  
def CrudGenerator(request):

    data_dict = {}
    if(request.method == 'POST'):
        Table_Name = request.POST['Table']
        name = request.POST['name']
        d_type = request.POST['d_type']
        
        data_dict = dict(request.POST.lists())

        with open('CRUD.csv', 'a', newline='') as response:
            flag = 0
            writer = csv.writer(response)

            with open('CRUD.csv', 'r') as read_obj:
                one_char = read_obj.read(1)

                if not one_char:
                    flag = 1

            if flag == 1:
                writer.writerow(data_dict.keys())

            if flag == 1 or (flag == 0 and data_dict['Table'][0] not in list(set(pd.read_csv('CRUD.csv')['Table']))):
                data_dict['Table'] = data_dict['Table'] * len(data_dict['name'])
                writer.writerows(zip_longest(*data_dict.values()))
                messages.success(request, "Crud created successfully ")

            else:
                messages.error(request, f"The Table structure named '{data_dict['Table'][0]}' has already been defined")
        
    return render(request, "admin_dashboard/CRUD/crud2.html")

# Crud function 
@login_required(login_url='/') 
def CrudExtension(request):
    tables = None

    if Path("CRUD.csv").exists():
        tables = list(set(pd.read_csv('CRUD.csv')['Table']))

    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : tables})
    
def Addadmin(request):
    if(request.method == 'POST'):
        First_Name = request.POST['first_name']
        Last_Name = request.POST['last_name']
        Username = request.POST['username']
        email = request.POST['email_address']
        password = request.POST.get('Password')
        confirm_password = request.POST['confirm_password']
        
        if(password==confirm_password):
            if(User.objects.filter(email=email).exists()):
                messages.error(request,'Email Taken')
                return render(request, "admin/add_admin.html")


            elif(User.objects.filter(username=Username).exists()):
                messages.error(request,'Username Taken')
                return render(request, "admin/add_admin.html")

            else:
                if(password_validate(request,password)):
                    user = User.objects.create_user(first_name = First_Name,last_name = Last_Name, username = Username, email = email, password = password)
                    user.is_active = False
                    user.is_staff = True
                    user.is_superuser = True
                    user.save()
                    
                    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                    domain = get_current_site(request).domain
                    link = reverse('activate', kwargs = {'uidb64' : uidb64, 'token' : token_generator.make_token(user)})
                    activate_url = 'http://' + domain + link

                    email = EmailMessage(
                        'Account Activation',
                        'Hello ' + Username + ' you can use the following link to activate your account.\n\n' + activate_url,
                        'from@example.com',
                        [email],
                    )
                    email.send(fail_silently = False)

                    messages.success(request,'Account activation mail has been sent')
                    return render(request, "admin/add_admin.html")
                else:
                     # return templage to dom using render function
                    return render(request, "admin/add_admin.html")
        else:
            messages.error(request,'Password Does Not Match')
            return render(request, "admin/add_admin.html")
    else:
        # return templage to dom using render function
        return render(request, "admin/add_admin.html")

     
    
#<-------------AdminList view----------------------------->
#<-----------------------AdminList View------------------------->   


def view_profile(request):
    user = User.objects.get(id = request.user.id)
    if(request.method == 'POST'):
        Username = request.POST['username']
        First_name= request.POST['first_name']
        Last_name = request.POST['last_name']
        Email = request.POST.get('email_address')
        user.username = Username
        user.first_name = First_name
        user.last_name = Last_name
        user.email = Email
        user.save()
        messages.success(request,"Profile is updated successuflly")
 
    return render(request, "profile/view_profile.html",{'user':user})


# <---- class based views --------------------------------->

class passwordChangingForm(PasswordChangeForm):
    old_password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control','type':'password'}))
    new_password1 = forms.CharField(max_length=100,widget= forms.PasswordInput(attrs= {'class':'form-control','type':'password'}))
    new_password2= forms.CharField(max_length=100,widget= forms.PasswordInput(attrs= {'class':'form-control','type':'password'}))

    class Meta:
        model = User
        fields = ('old_password','new_password1','new_password2')    


class PasswordsChangesView(PasswordChangeView):
    form_class =passwordChangingForm
    success_url = reverse_lazy('login')


# <---------------------end ----------------------------------->
@login_required(login_url='/') 
def module_setting(request):
    return render(request, "roles_and_permission/module_setting.html")

def admin_roles_and_permission(request):
    return render(request, "roles_and_permission/admin_roles_and_permission.html")

@login_required(login_url='/') 
def general_settings(request):
    return render(request, "settings/general_settings.html")

@login_required(login_url='/') 
def admintest(request):
    user = User.objects.all()
    count = -1
    if(request.method == 'POST'):
        user_id = request.POST['user_id']
        admin = User.objects.get(id = user_id)
        admin.delete()
        messages.success(request,"Admin deleted successfully!!!")
    return render(request,"admin/admin_test.html",{'users':user,"count":count})

def EditAdminList(request,user_id):
        user = User.objects.all()
        count = User.objects.get(id = user_id)
        return render(request,"admin/admin_test.html",{'users':user,"count":count})

@login_required(login_url='/') 
def EditAdminListValue(request):
   
    if(request.method == 'POST'):
        userid = request.POST.get('user')
        user = User.objects.get(id  = userid)
        Email = request.POST.get('email_address')
        Role = request.POST['role']
        Status = request.POST.get('status')
        user.email = Email
        user.role = Role
        user.status = False
        if(Status == "on"):
            user.status = True
        user.save()
        messages.success(request,"Admin Updated successfully!!!")
    return redirect('admintest')

def calendar(request):
    return render(request,"admin_dashboard/pages/calendar.html")
# Role and Permission
def RolePermission(request):
    return render(request, "roles_and_permission/role_and_permissions.html")

# <---- General Settings View --------------------------------->
# with open("settings.json","r") as p:
#     parm = json.load(p)["json_files/general_settings"]

# def generl_settings_conf(param):
#     print(parm)    

def general_settings(request):

    return render(request, "settings/general_settings.html")

def add_new_role(request):

    return render(request, "roles_and_permission/add_new_role.html")

 # <--------------------------module settings------------------------------>
@login_required(login_url='/') 
def module_setting(request):
    user = User.objects.all()
    return render(request, "roles_and_permission/module_setting.html",{"users":user})
    #< --------------------------end------------------------------------->

def create_table(request, table):
    if request.method == 'POST':

        df = pd.read_csv('CRUD.csv')
        ans_df = df.loc[df['Table'] == table]

        query = f"CREATE TABLE IF NOT EXISTS {table} ("

        for index in range(len(ans_df)):
            query += f"{ans_df.iloc[index, 2]} {ans_df.iloc[index, 3]}, "

        query = query[ : -2] + ")"

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(query)
        conn.commit()
        conn.close()

        messages.success(request, "Crud Installed Successfully ")
        
    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : list(set(pd.read_csv('CRUD.csv')['Table']))})

def drop_table(request, table):
    if request.method == 'POST':

        df = pd.read_csv('CRUD.csv')
        ans_df = df.loc[df['Table'] == table]

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(f"DROP TABLE IF EXISTS {table}")
        conn.commit()
        conn.close()

        messages.success(request, "Crud Uninstalled Successfully ")
        
    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : list(set(pd.read_csv('CRUD.csv')['Table']))})

def delete_crud(request, table):
    if request.method == 'POST':

        df = pd.read_csv('CRUD.csv')
        df.drop(df.index[(df["Table"] == table)], axis = 0, inplace = True)
        df.to_csv('CRUD.csv', index = False)

        with open('CRUD.csv', 'a', newline='') as response:
            writer = csv.writer(response)
            
        messages.success(request, "Crud has been removed successfully")
        
    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : list(set(pd.read_csv('CRUD.csv')['Table']))})
import datetime
from django.contrib.auth import models, get_user_model
from django.forms import fields
from django import forms
from django.http import request
from django.shortcuts import render,redirect,HttpResponse
from django.contrib.auth.models import User,auth
from .models import Module,general_setting, email_settings, recaptcha_settings
from django.contrib import messages
from django.core.mail import EmailMessage, message
from django.core.mail.backends.smtp import EmailBackend
from django.urls.base import reverse_lazy
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
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
    update_log(User.objects.get(id = request.user.id).username, "Opened and viewed Dashboard V1")

    return render(request,'admin_dashboard/DashBoard_1.html', {'user' : user, "count" : count, 'tables' : installed_tables(), "gen" : gen_data()})

# DashBoard 2 view in  home page
@login_required(login_url='/') 
def DashBoardTwo(request):
    user = User.objects.get(id = request.user.id)
    update_log(User.objects.get(id = request.user.id).username, "Opened and viewed Dashboard V2")

    return render(request,'admin_dashboard/DashBoard_2.html', {'user' : user, 'tables' : installed_tables(), "gen" : gen_data()})

# DashBoard 3 view in  home page
@login_required(login_url='/') 
def DashBoardThree(request):
    user = User.objects.get(id = request.user.id)
    update_log(User.objects.get(id = request.user.id).username, "Opened and viewed Dashboard V3")

    return render(request,'admin_dashboard/DashBoard_3.html', {'user' : user, 'tables' : installed_tables(), "gen" : gen_data()})

# <------------------------------------ End of Area------------------------------>

def LogOut(request):
    update_log(User.objects.get(id = request.user.id).username, "Logged Out")
    auth.logout(request)
    return redirect('/')

# Login view for login page
def Login(request):
    if(request.method=='POST'):
        Password = request.POST['password']
        Username = request.POST['username'].strip()
        user = auth.authenticate(username=Username, password=Password)
        
        if(user is not None and user.is_active):
            auth.login(request, user)
            update_log(User.objects.get(id = request.user.id).username, "Logged In")
            # if(request.POST.get('chk')):
            #     response = HttpResponse('DashBoard')
            #     response.set_cookie('cid',Username)
            #     response.set_cookie('cid1',Password)
            #     return response
            
            # if(request.COOKIES.get('cid')):
            #     return render(request,'accounts/login.html',{'cookie1':request.COOKIES.get('cid'),'cookie2':request.COOKIES.get('cid1')})
            # else:
            return redirect('DashBoard')

        else:
            messages.error(request,'Login Failed! ')
            return render(request,'accounts/login.html')
    else:
        return render(request, 'accounts/login.html', {"gen" : gen_data(), 'tables' : installed_tables()})

# Register view  for register page
def Register(request):
    if(request.method == 'POST'):
        First_Name = request.POST['first_name'].strip()
        Last_Name = request.POST['last_name'].strip()
        Username = request.POST['user_name'].strip()
        email = request.POST['email_address'].strip()
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

                    data = str(email_settings.objects.get())
                    eml = data.split()
                    
                    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                    domain = get_current_site(request).domain
                    link = reverse('activate', kwargs = {'uidb64' : uidb64, 'token' : token_generator.make_token(user)})
                    activate_url = 'http://' + domain + link

                    backend = EmailBackend(host = eml[1], port = eml[2], username = eml[3], password = eml[4], fail_silently = False)
                    
                    email = EmailMessage(
                        'Account Activation',
                        'Hello ' + Username + ' you can use the following link to activate your account.\n\n' + activate_url,
                        'from@example.com',
                        [email],
                        connection = backend,
                    )

                    email.send()

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

            if not token_generator.check_token(user, token):
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
def CrudList(request, table):
    rows = None
    columns = None
    
    if not table.startswith('{'):
        update_log(User.objects.get(id = request.user.id).username, f'Opened and viewed Installed CRUD : "{table}"')

        df = pd.read_csv('CRUD.csv')
        columns = ['S. No.'] + list(df.loc[(df["Table"] == table), 'name'])

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(f'SELECT * FROM "{table}"')
        rows = pd.DataFrame(c.fetchall()) 

        conn.commit()
        conn.close()       
        
    return render(request, "admin_dashboard/CRUD/crud1.html", {'tables' : installed_tables(), 'rows' : rows, 'columns' : columns, 'tname' : table, "gen" : gen_data()})

# Crud function
@login_required(login_url='/')  
def CrudGenerator(request):
    data_dict = {}
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed CRUD Generator')
    
    if(request.method == 'POST'):
        data_dict = dict(request.POST.lists())
        data_dict['Table'] = [name.strip() for name in data_dict['Table']]
        data_dict['name'] = [names.strip() for names in data_dict['name']] 

        if "/" in data_dict['Table'][0] or "'" in data_dict['Table'][0] or '"' in data_dict['Table'][0] or "." in data_dict['Table'][0]:
            messages.error(request, """Table Name cannot contain these characters ( / or ' or " or . )""")
            return render(request, "admin_dashboard/CRUD/crud2.html", {'tables' : installed_tables(), "gen" : gen_data()})

        for col_name in data_dict['name']:
            if "/" in col_name or "'" in col_name or '"' in col_name or "." in col_name:
                messages.error(request, """Field Name cannot contain these characters ( / or ' or " or . )""")
                return render(request, "admin_dashboard/CRUD/crud2.html", {'tables' : installed_tables(), "gen" : gen_data()})

        if len(set(data_dict['name'])) != len(data_dict['d_type']):
            messages.error(request, f"Two or more fields have the same name, all fields must have a unique name")
            return render(request, "admin_dashboard/CRUD/crud2.html", {'tables' : installed_tables(), "gen" : gen_data()})

        with open('CRUD.csv', 'a', newline='') as response:
            flag = 0
            writer = csv.writer(response)

            with open('CRUD.csv', 'r') as read_obj:
                one_char = read_obj.read(1)

                if not one_char:
                    flag = 1

            if flag == 1:
                data_dict['Updated_at'] = []
                writer.writerow(data_dict.keys())

            if flag == 1 or (flag == 0 and data_dict['Table'][0] not in list(set(pd.read_csv('CRUD.csv')['Table']))):
                data_dict['Table'] = data_dict['Table'] * len(data_dict['name'])
                data_dict['Updated_at'] = [str(datetime.datetime.now().isoformat(' ', 'seconds'))] * len(data_dict['name'])
                writer.writerows(zip_longest(*data_dict.values()))

                update_log(User.objects.get(id = request.user.id).username, f'Created CRUD : "{data_dict["Table"][0]}"')
                messages.success(request, f'CRUD : "{data_dict["Table"][0]}" has been created successfully')

            else:
                messages.error(request, f'The CRUD structure named "{data_dict["Table"][0]}" has already been defined')
        
    return render(request, "admin_dashboard/CRUD/crud2.html", {'tables' : installed_tables(), "gen" : gen_data()})

# Crud function 
@login_required(login_url='/') 
def CrudExtension(request):
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed CRUD Extension')
    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : installed_tables(), "gen" : gen_data()})
    
def Addadmin(request):
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed Add Admin')

    if(request.method == 'POST'):
        First_Name = request.POST['first_name'].strip()
        Last_Name = request.POST['last_name'].strip()
        Username = request.POST['username'].strip()
        email = request.POST['email_address'].strip()
        password = request.POST.get('Password')
        confirm_password = request.POST['confirm_password']
        
        if(password==confirm_password):
            if(User.objects.filter(email=email).exists()):
                messages.error(request,'Email Taken')
                return render(request, "admin/add_admin.html", {"gen" : gen_data(), 'tables' : installed_tables()})


            elif(User.objects.filter(username=Username).exists()):
                messages.error(request,'Username Taken')
                return render(request, "admin/add_admin.html", {"gen" : gen_data(), 'tables' : installed_tables()})

            else:
                if(password_validate(request,password)):
                    user = User.objects.create_user(first_name = First_Name,last_name = Last_Name, username = Username, email = email, password = password)
                    user.is_active = False
                    user.is_staff = True
                    user.is_superuser = True
                    user.save()

                    data = str(email_settings.objects.get())
                    eml = data.split()
                    
                    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                    domain = get_current_site(request).domain
                    link = reverse('activate', kwargs = {'uidb64' : uidb64, 'token' : token_generator.make_token(user)})
                    activate_url = 'http://' + domain + link

                    backend = EmailBackend(host = eml[1], port = eml[2], username = eml[3], password = eml[4], fail_silently = False)
                    
                    email = EmailMessage(
                        'Account Activation',
                        'Hello ' + Username + ' you can use the following link to activate your account.\n\n' + activate_url,
                        'from@example.com',
                        [email],
                        connection = backend,
                    )

                    email.send()

                    messages.success(request,'Account activation mail has been sent')
                    return render(request, "admin/add_admin.html", {"gen" : gen_data(), 'tables' : installed_tables()})
                else:
                     # return templage to dom using render function
                    return render(request, "admin/add_admin.html", {"gen" : gen_data(), 'tables' : installed_tables()})
        else:
            messages.error(request,'Password Does Not Match')
            return render(request, "admin/add_admin.html", {"gen" : gen_data(), 'tables' : installed_tables()})
    else:
        # return templage to dom using render function
        return render(request, "admin/add_admin.html", {'tables' : installed_tables(), "gen" : gen_data()})

     
    
#<-------------AdminList view----------------------------->
#<-----------------------AdminList View------------------------->   


def view_profile(request):
    user = User.objects.get(id = request.user.id)
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed Profile')

    if(request.method == 'POST'):
        Username = request.POST['username'].strip()
        First_name= request.POST['first_name'].strip()
        Last_name = request.POST['last_name'].strip()
        Email = request.POST.get('email_address').strip()
        if(Username):
            if(Username == user.username):
                 user.username = Username
            elif(User.objects.filter(username=Username).exists()):
                messages.error(request,'Username Taken')
                return redirect("view_profile")
        
        user.first_name = First_name
        user.last_name = Last_name
        user.email = Email
        user.save()
        update_log(User.objects.get(id = request.user.id).username, 'Updated Profile')
        messages.success(request,"Profile updated successfully")
 
    return render(request, "profile/view_profile.html", {'user': user, 'tables' : installed_tables(), "gen" : gen_data()})


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

# <---------------------General Settings  ----------------------------------->
triger = True
@login_required(login_url='/') 
def general_settings(request):
    global triger
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed General Settings')

    gen = general_setting.objects.all()
    if(len(gen)>0):
        gen = general_setting.objects.all()[0]

    if(request.method == 'POST'):
        application_name = request.POST['application_name'].strip()
        timezone = request.POST['timezone'].strip()
        language = request.POST['language']
        logo = ""
        favicon = ""
        
        if("logo" in request.FILES):
            logo= request.FILES['logo']
           
        if("favicon" in request.FILES):
            favicon = request.FILES['favicon']

        if(triger==False):
            gen = general_setting.objects.all()[0]
            if(favicon):
                gen.favicon=  favicon
            if(logo):
                gen.logo=  logo
            gen.Application_Name = application_name
            gen.language = language
            gen.save()
           
            update_log(User.objects.get(id = request.user.id).username, 'Updated General Settings')
            messages.success(request,"Data Updated successfully")
            return redirect("general_settings")
       
        triger = False
        gen = general_setting(logo = logo,favicon = favicon,Application_Name = application_name,timezone = timezone,Default_language = language)
        gen.save()
        gen = general_setting.objects.all()

        if(len(gen)>1):
                gen = general_setting.objects.all()[1]
                gen.delete()

        update_log(User.objects.get(id = request.user.id).username, 'Data inserted in General Settings')
        messages.success(request,"Data inserted successfully")
        return redirect("general_settings")
        
    return render(request, "settings/general_settings.html", {'tables' : installed_tables(), "gen" : gen})


# Email Settings
@login_required(login_url='/') 
def EmailSettings(request):
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed Email Settings')

    if(request.method == 'POST'):
        email_from = request.POST['email_from'].strip()
        smtp_host = request.POST['smtp_host'].strip()
        smtp_port = request.POST['smtp_port'].strip()
        smtp_user = request.POST['smtp_user'].strip()
        smtp_pass = request.POST['smtp_pass'].strip()

        if " " in email_from:
            messages.error(request, 'Email From/ Reply to cannot have spaces in it')
            return render(request, "settings/Email_Settings.html", {"gen" : gen_data(), 'tables' : installed_tables()})

        if " " in smtp_host:
            messages.error(request, 'SMTP Host cannot have spaces in it')
            return render(request, "settings/Email_Settings.html", {"gen" : gen_data(), 'tables' : installed_tables()})

        if(email_settings.objects.exists()):    
            email_settings.objects.all().delete()    

        eml = email_settings()
        eml.email_from = email_from
        eml.smtp_host = smtp_host
        eml.smtp_pass = smtp_pass
        eml.smtp_port = smtp_port
        eml.smtp_user = smtp_user
        eml.save()

        update_log(User.objects.get(id = request.user.id).username, 'Updated Email Settings')
        messages.success(request, "Email Settings updated successfully")

    return render(request, "settings/Email_Settings.html", {"gen" : gen_data(), 'tables' : installed_tables()})

# Google reCAPTCHA
@login_required(login_url='/') 
def reCAPTCHA(request):
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed Google reCAPTCHA Settings')

    if(request.method == 'POST'):
        recaptcha_site_key = request.POST['recaptcha_site_key'].strip()
        recaptcha_secret_key = request.POST['recaptcha_secret_key'].strip()
        recaptcha_lang = request.POST['recaptcha_lang'].strip()

        if(recaptcha_settings.objects.exists()):    
            recaptcha_settings.objects.all().delete()    

        rep = recaptcha_settings()
        rep.recaptcha_site_key = recaptcha_site_key
        rep.recaptcha_secret_key = recaptcha_secret_key
        rep.recaptcha_lang = recaptcha_lang
        rep.save()

        update_log(User.objects.get(id = request.user.id).username, 'Updated reCAPTCHA Settings')
        messages.success(request, "reCAPTCHA Settings updated successfully")

    return render(request,"settings/google_recaptcha.html", {"gen" : gen_data(), 'tables' : installed_tables()})


# <------------------------------Admin List functions ---------------------------------->
@login_required(login_url='/') 
def admintest(request):
    user = User.objects.all()
    module = Module.objects.all()
    count = -1

    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed Admin List')
    return render(request, "admin/admin_test.html", {'users' : user, "count" : count, "modules" : module, 'tables' : installed_tables(), "gen" : gen_data()})

def filterAdminList(request):
    module = Module.objects.all()
    user = User.objects.all()

    if(request.method =='POST'):
        update_log(User.objects.get(id = request.user.id).username, 'Performed search in Admin List')
        all_status = request.POST.get('allstatus[]')
        admin_status = request.POST.get('addadmintypes[]')
       
        if(all_status):
            if(all_status=="Active"):
                user = User.objects.filter(is_active =True)
            else:
                user = User.objects.filter(is_active =False)
        if(admin_status):
            user = User.objects.filter(role = admin_status)

    return render(request, "admin/admin_test.html", {'users' : user, "modules" : module, 'tables' : installed_tables(), "gen" : gen_data()})

def EditAdminList(request,user_id):
        module = Module.objects.all()
        user = User.objects.all()
        count = User.objects.get(id = user_id)

        return render(request, "admin/admin_test.html", {'users' : user, "count" : count, "modules" : module, 'tables' : installed_tables(), "gen" : gen_data()})

@login_required(login_url='/') 
def EditAdminListValue(request):
    if(request.method == 'POST'):
        userid = request.POST.get('user').strip()
        user = User.objects.get(id  = userid)
        Email = request.POST.get('email_address').strip()
        Role = request.POST['role'].strip()
        Status = request.POST.get('status')
        user.email = Email
        user.role = Role
        user.status = False

        if(Status == None):
            user.is_activate = True

        user.save()
        update_log(User.objects.get(id = request.user.id).username, f'Updated Admin Details : "{user}"')
        messages.success(request,"Admin Updated successfully!!!")

    return redirect('admintest')

def delete_admin(request,user_id):
    user = User.objects.get(id=  user_id)

    if(request.method =='GET'):
        update_log(User.objects.get(id = request.user.id).username, f'Deleted Admin : "{user}"')
        user.delete()
        messages.success(request,"Admin deleted successfully")

        return redirect("admintest")
# <---------------------------------end of code---------------------------------------->
def calendar(request):
    update_log(User.objects.get(id = request.user.id).username, "Opened and viewed Calendar")
    return render(request, "admin_dashboard/pages/calendar.html", {'tables' : installed_tables(), "gen" : gen_data()})

# <------------------end of code------------------------------------------->

# <---------------------Admin role view -------------------------------------->
def add_new_role(request):
    update_log(User.objects.get(id = request.user.id).username, "Opened and viewed Add new Role")

    if(request.method == "POST"):
        admin_title = request.POST["admin_role_title"].strip()
        status = request.POST["admin_role_status"]
        module = Module(module_name = admin_title)
        module.save()
        update_log(User.objects.get(id = request.user.id).username, f'Created new Admin Role : "{admin_title}"')
        messages.success(request,"New Admin Role created successfully!!!!")
        return redirect("admin_roles_and_permission")

    return render(request, "roles_and_permission/add_new_role.html", {'tables' : installed_tables(), "gen" : gen_data()})

def edit_new_role(request,module_id):
    module = Module.objects.get(id = module_id)
    count = -1

    if(request.method =="POST"):
        admin_title = request.POST["admin_role_title"].strip()
        status = request.POST["admin_role_status"]
        module.module_name = admin_title
        module.save()
        update_log(User.objects.get(id = request.user.id).username, f'Updated Admin Role to "{admin_title}"')
        messages.success(request,"Admin role updated!!")
        return redirect("admin_roles_and_permission")

    return render(request, "roles_and_permission/add_new_role.html", {"count" : count, "module" : module, 'tables' : installed_tables(), "gen" : gen_data()})

def delete_role(request,module_id):
    module = Module.objects.get(id = module_id)

    if(request.method == "GET"):
        update_log(User.objects.get(id = request.user.id).username, f'Deleted Admin Role')
        module.delete()
        messages.success(request,"Role deleted successfully!!!")

        return redirect("admin_roles_and_permission")

 # <--------------------------roles and permission settings------------------------------>
@login_required(login_url='/') 
def module_setting(request):
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed Module Settings')
    user = User.objects.all()
    return render(request, "roles_and_permission/module_setting.html", {"users" : user, 'tables' : installed_tables(), "gen" : gen_data()})

def admin_roles_and_permission(request):
    module = Module.objects.all()
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed Add new Role')
    return render(request, "roles_and_permission/admin_roles_and_permission.html", {"modules" : module, 'tables' : installed_tables(), "gen" : gen_data()})

def RolePermission(request):
    update_log(User.objects.get(id = request.user.id).username, 'Opened and viewed Roles & Permissions')
    return render(request, "roles_and_permission/role_and_permissions.html", {'tables' : installed_tables(), "gen" : gen_data()})

    #< --------------------------end------------------------------------->

# <---------------------Crud section ------------------------------------->

def create_table(request, table):
    if request.method == 'POST':

        if check_status(table) == [1]:
            messages.error(request,f'CRUD : "{table}" is already installed')
            return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : installed_tables(), "gen" : gen_data()})

        df = pd.read_csv('CRUD.csv')
        ans_df = df.loc[df['Table'] == table]

        query = f'CREATE TABLE IF NOT EXISTS "{table}" (ID INTEGER PRIMARY KEY AUTOINCREMENT, '

        for index in range(len(ans_df)):
            query += f'"{ans_df.iloc[index, 2]}" {ans_df.iloc[index, 3]}, '

        query = query[ : -2] + ")"

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(query)
        conn.commit()
        conn.close()
        
        df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds'))
        df.to_csv('CRUD.csv', index = False)

        update_log(User.objects.get(id = request.user.id).username, f'Installed CRUD : "{table}"')
        messages.success(request, f'CRUD : "{table}" has been installed successfully')
        
    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : installed_tables(), "gen" : gen_data()})

def drop_table(request, table):
    if request.method == 'POST':

        if check_status(table) == [0]:
            messages.error(request,f'CRUD : "{table}" is already uninstalled')
            return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : installed_tables(), "gen" : gen_data()})

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(f'DROP TABLE IF EXISTS "{table}"')
        conn.commit()
        conn.close()

        df = pd.read_csv('CRUD.csv')
        df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds'))
        df.to_csv('CRUD.csv', index = False)

        update_log(User.objects.get(id = request.user.id).username, f'Uninstalled CRUD : "{table}"')
        messages.success(request, f'CRUD : "{table}" has been uninstalled successfully')
        
    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : installed_tables(), "gen" : gen_data()})

def delete_crud(request, table):
    if request.method == 'POST':

        if check_status(table) == [1]:
            messages.error(request,f'The CRUD : "{table}" that you want to delete is still installed')
            return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : installed_tables(), "gen" : gen_data()})

        df = pd.read_csv('CRUD.csv')
        df.drop(df.index[(df["Table"] == table)], axis = 0, inplace = True)
        df.to_csv('CRUD.csv', index = False)

        with open('CRUD.csv', 'a', newline='') as response:
            writer = csv.writer(response)
            update_log(User.objects.get(id = request.user.id).username, f'Deleted CRUD : "{table}"')
            messages.success(request, f'CRUD : "{table}" has been deleted successfully')
            
    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : installed_tables(), "gen" : gen_data()})

def check_status(tables):
    status = []
    conn = sqlite3.connect('CRUD.db')
    c = conn.cursor()

    if isinstance(tables, str):
        c.execute(f'SELECT count(*) FROM sqlite_master WHERE type="table" AND name="{tables}"')
        return list(c.fetchone())

    for table in tables:
        c.execute(f'SELECT count(*) FROM sqlite_master WHERE type="table" AND name="{table}"')
        status += list(c.fetchone())

    conn.commit()
    conn.close()

    return ["Active" if val == 1 else "Inactive" for val in status]

def installed_tables():
    tables = None

    if Path("CRUD.csv").exists():
        tables = list(dict.fromkeys(pd.read_csv('CRUD.csv', error_bad_lines=False)['Table']))
        updated_at = list(dict.fromkeys(pd.read_csv('CRUD.csv', error_bad_lines=False)['Updated_at']))
        df = pd.DataFrame(list(zip(tables, check_status(tables), updated_at)), columns = ['name', 'status', 'updated_at'])
        tables = json.loads(df.reset_index().to_json(orient = 'records'))

    return tables

def delete_all(request, table):
    rows = None
    columns = None

    if request.method == 'POST':
        df = pd.read_csv('CRUD.csv')
        columns = ['S. No.'] + list(df.loc[(df["Table"] == table), 'name'])

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(f'SELECT count(*) FROM (select 0 from "{table}" limit 1)')

        if (list(c.fetchone()) == [0]):
            conn.commit()
            conn.close()
            messages.error(request, f'CRUD : "{table}" is already empty')
            return render(request, "admin_dashboard/CRUD/crud1.html", {'tables' : installed_tables(), 'rows' : rows, 'columns' : columns, 'tname' : table, "gen" : gen_data()})

        c.execute(f'DELETE FROM "{table}"')
        conn.commit()
        df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds')) 
        c.execute(f'SELECT * FROM "{table}"')
        rows = pd.DataFrame(c.fetchall())

        conn.commit()
        conn.close()
        df.to_csv('CRUD.csv', index = False)
        update_log(User.objects.get(id = request.user.id).username, f'Deleted all the data from CRUD : "{table}"')
        messages.success(request, f'All the data has been deleted from CRUD : "{table}" successfully')
        
    return render(request, "admin_dashboard/CRUD/crud1.html", {'tables' : installed_tables(), 'rows' : rows, 'columns' : columns, 'tname' : table, "gen" : gen_data()})
    
def delete_row(request, table, row_id):
    rows = None
    columns = None

    if not table.startswith('{'):
        df = pd.read_csv('CRUD.csv')
        columns = ['S. No.'] + list(df.loc[(df["Table"] == table), 'name'])

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(f'DELETE FROM "{table}" WHERE ID = {row_id}')
        conn.commit()

        df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds')) 
        c.execute(f'SELECT * FROM "{table}"')
        rows = pd.DataFrame(c.fetchall())

        conn.commit()
        conn.close()
        df.to_csv('CRUD.csv', index = False)

    update_log(User.objects.get(id = request.user.id).username, f'Deleted Row No. {row_id} from CRUD : "{table}"')
    messages.success(request, f'Row No. {row_id} has been deleted from CRUD : "{table}" successfully')

    return render(request, "admin_dashboard/CRUD/crud1.html", {'tables' : installed_tables(), 'rows' : rows, 'columns' : columns, 'tname' : table, "gen" : gen_data()})

def insert_record(request, table):
    rows = None
    columns = None

    if request.method == 'POST':
        df = pd.read_csv('CRUD.csv')
        columns = ['S. No.'] + list(df.loc[(df["Table"] == table), 'name'])
        data_dict = dict(request.POST.lists())
        
        query = f'INSERT INTO "{table}" VALUES (NULL, '

        for value in data_dict['column_values']:
            if '"' in value.strip():
                messages.error(request, """Column data cannot contain " " you can use ' ' instead""")
                return render(request, "admin_dashboard/CRUD/CRUD_Insert.html", {'tables' : installed_tables(), 'tname' : table, 'table' : insert_data(table), 'edit' : None, "gen" : gen_data(), 'title' : " | Insert Record"})
            
            query += f'"{value.strip()}", '

        query = query[ : -2] + ")"

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(query)
        conn.commit()

        df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds'))
        c.execute(f'SELECT * FROM "{table}"')
        rows = pd.DataFrame(c.fetchall())

        conn.commit()
        conn.close()
        df.to_csv('CRUD.csv', index = False)

        update_log(User.objects.get(id = request.user.id).username, f'Record inserted into CRUD : "{table}"')
        messages.success(request, f'Record inserted into CRUD : "{table}" successfully')

    else:
        if not table.startswith('{'):
            update_log(User.objects.get(id = request.user.id).username, f'Opened and viewed Insert Record in CRUD : "{table}"')
            return render(request, "admin_dashboard/CRUD/CRUD_Insert.html", {'tables' : installed_tables(), 'tname' : table, 'table' : insert_data(table), 'edit' : None, "gen" : gen_data(), 'title' : " | Insert Record"})

    return render(request, "admin_dashboard/CRUD/crud1.html", {'tables' : installed_tables(), 'rows' : rows, 'columns' : columns, 'tname' : table, "gen" : gen_data()})

def edit_record(request, table, row_id):
    rows = None
    columns = None

    if request.method == 'POST':
        df = pd.read_csv('CRUD.csv')
        columns = ['S. No.'] + list(df.loc[(df["Table"] == table), 'name'])
        data_dict = dict(request.POST.lists())
        ans_df = pd.DataFrame(list(zip(list(df.loc[(df["Table"] == table), 'name']), data_dict['column_values'])), columns = ['column_name', 'column_value'])

        query = f'UPDATE "{table}" SET '

        for index in range(len(ans_df)):
            if '"' in ans_df.iloc[index, 1].strip():
                messages.error(request, """Column data cannot contain " " you can use ' ' instead""")
                return render(request, "admin_dashboard/CRUD/CRUD_Insert.html", {'tables' : installed_tables(), 'tname' : table, 'table' : edit_data(table, row_id), 'edit' : True, 'row_id' : row_id, 'title' : " | Edit Record", "gen" : gen_data()})

            query += f'"{ans_df.iloc[index, 0]}" = "{ans_df.iloc[index, 1].strip()}", '

        query = query[ : -2] + f" WHERE ID = {row_id}"

        conn = sqlite3.connect('CRUD.db')
        c = conn.cursor()
        c.execute(query)
        conn.commit()

        df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds'))
        c.execute(f'SELECT * FROM "{table}"')
        rows = pd.DataFrame(c.fetchall())

        conn.commit()
        conn.close()
        df.to_csv('CRUD.csv', index = False)

        update_log(User.objects.get(id = request.user.id).username, f'Updated Row No. {row_id} in CRUD : "{table}"')
        messages.success(request, f'Row No. {row_id} has been updated successfully')

    else:
        if not table.startswith('{'):
            update_log(User.objects.get(id = request.user.id).username, f'Opened and viewed Edit Record in CRUD : "{table}"')
            return render(request, "admin_dashboard/CRUD/CRUD_Insert.html", {'tables' : installed_tables(), 'tname' : table, 'table' : edit_data(table, row_id), 'edit' : True, 'row_id' : row_id, 'title' : " | Edit Record", "gen" : gen_data()})
    
    return render(request, "admin_dashboard/CRUD/crud1.html", {'tables' : installed_tables(), 'rows' : rows, 'columns' : columns, 'tname' : table, "gen" : gen_data()})

def insert_data(table):
    df = pd.read_csv('CRUD.csv')
    columns = list(df.loc[(df["Table"] == table), 'name'])
    f_type = list(df.loc[(df["Table"] == table), 'f_type'])
    d_type = list(df.loc[(df["Table"] == table), 'd_type'])
    
    df = pd.DataFrame(list(zip(columns, f_type, d_type)), columns = ['name', 'f_type', 'd_type'])
    data = json.loads(df.reset_index().to_json(orient = 'records'))
    
    return data

def edit_data(table, row_id):
    df = pd.read_csv('CRUD.csv')
    columns = list(df.loc[(df["Table"] == table), 'name'])
    f_type = list(df.loc[(df["Table"] == table), 'f_type'])
    d_type = list(df.loc[(df["Table"] == table), 'd_type'])

    conn = sqlite3.connect('CRUD.db')
    c = conn.cursor()
    c.execute(f'SELECT * FROM "{table}" WHERE ID = "{row_id}"')
    row = list(c.fetchone())

    conn.commit()
    conn.close()       
    
    df = pd.DataFrame(list(zip(columns, f_type, row[1 : ], d_type)), columns = ['name', 'f_type', 'value', 'd_type'])
    data = json.loads(df.reset_index().to_json(orient = 'records'))

    return data

def edit_crud(request, table):
    data = None

    if request.method == 'POST':
        df = pd.read_csv('CRUD.csv')
        columns = list(df.loc[(df["Table"] == table), 'name'])
        f_type = list(df.loc[(df["Table"] == table), 'f_type'])

        df = pd.DataFrame(list(zip(columns, f_type)), columns = ['name', 'f_type'])
        data = json.loads(df.reset_index().to_json(orient = 'records'))
        update_log(User.objects.get(id = request.user.id).username, f'Opened and viewed Edit CRUD : "{table}"')
        
    return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : data, "gen" : gen_data()})
            
def save_changes(request, table):
    if request.method == 'POST':
        df = pd.read_csv('CRUD.csv')
        columns = list(df.loc[(df["Table"] == table), 'name'])
        f_type = list(df.loc[(df["Table"] == table), 'f_type'])
        
        data_dict = dict(request.POST.lists())
        data_dict['Table'] = [name.strip() for name in data_dict['Table']]
        data_dict['name'] = [names.strip() for names in data_dict['name']]
        data_dict['new_name'] = [names.strip() for names in data_dict['new_name']]

        # checking errors 
        if "check_box" in data_dict:
            for del_column in data_dict['check_box']:
                if del_column not in data_dict['name'] or f_type != data_dict['f_type']:
                    messages.error(request, "You cannot delete and edit a column at the same time")
                    return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : error_data(table), "gen" : gen_data()})

        if ((data_dict['new_name'][0] != '' and ("new_d_type" not in data_dict or "new_f_type" not in data_dict)) or ("new_f_type" in data_dict and ("new_d_type" not in data_dict or data_dict['new_name'][0] == '')) or ("new_d_type" in data_dict and ("new_f_type" not in data_dict or data_dict['new_name'][0] == ''))):
            messages.error(request, "Fill all the fields to add a column")
            return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : error_data(table), "gen" : gen_data()})

        if len(data_dict['new_name']) > 1:
            for index in range (1, len(data_dict['new_name'])):
                if data_dict['new_name'][index] == '':
                    messages.error(request, "Fill all the fields to add a column")
                    return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : error_data(table), "gen" : gen_data()})

        if (data_dict['new_name'][0] != '' and "new_d_type" in data_dict and "new_f_type" in data_dict):
            if ((len(data_dict['new_name']) != len(data_dict['new_d_type'])) or (len(data_dict['new_d_type']) != len(data_dict['new_f_type'])) or (len(data_dict['new_f_type']) != len(data_dict['new_name']))): 
                messages.error(request, "Fill all the fields to add a column")
                return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : error_data(table), "gen" : gen_data()})

        if (data_dict['new_name'][0] == '' and "new_d_type" not in data_dict and "new_f_type" not in data_dict and "check_box" in data_dict):
            if len(data_dict["check_box"]) == len(data_dict['name']):
                messages.error(request, "You cannot delete all the columns from a table")
                return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : error_data(table), "gen" : gen_data()})
        
        if "/" in data_dict['Table'][0] or "'" in data_dict['Table'][0] or '"' in data_dict['Table'][0] or "." in data_dict['Table'][0]:
            messages.error(request, """Table Name cannot contain these characters ( / or ' or " or . )""")
            return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : error_data(table), "gen" : gen_data()})
        
        for col_name in (data_dict['name'] + data_dict['new_name']):
            if "/" in col_name or "'" in col_name or '"' in col_name or "." in col_name:
                messages.error(request, """Field Name cannot contain these characters ( / or ' or " or . )""")
                return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : error_data(table), "gen" : gen_data()})

        if (len(set(data_dict['name'])) != len(data_dict['f_type'])) or ("new_f_type" in data_dict and len(set(data_dict['name'] + data_dict['new_name'])) != len(data_dict['f_type'] + data_dict['new_f_type'])):
            messages.error(request, f"Two or more fields have the same name, all fields must have a unique name")
            return render(request, "admin_dashboard/CRUD/CRUD_Editor.html", {'tables' : installed_tables(), 'tname' : table, 'table' : error_data(table), "gen" : gen_data()})
    
        # edit column
        if data_dict['name'] != columns or data_dict['f_type'] != f_type:
            for index in range(len(data_dict['name'])):
                if data_dict['name'][index] != columns[index]:
                    if check_status(table) == [1]:
                        conn = sqlite3.connect('CRUD.db')
                        c = conn.cursor()

                        c.execute(f'ALTER TABLE "{table}" RENAME COLUMN "{columns[index]}" TO "{data_dict["name"][index]}"')
                        
                        conn.commit()
                        conn.close()

                    df = pd.read_csv('CRUD.csv')
                    df.loc[(df['Table'] == table) & (df['name'] == columns[index]), ['name']] = str(data_dict["name"][index])
                    df.loc[(df['Table'] == table) & (df['f_type'] == f_type[index]), ['f_type']] = str(data_dict["f_type"][index])
                    df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds'))
                    df.to_csv('CRUD.csv', index = False)

        # delete column
        if "check_box" in data_dict:
            df = pd.read_csv('CRUD.csv')
            ans_df = df.loc[df['Table'] == table]

            query = 'CREATE TABLE IF NOT EXISTS "FAKE" (ID INTEGER PRIMARY KEY AUTOINCREMENT, '
            select_query = 'INSERT INTO FAKE SELECT ID, '

            for index in range(len(ans_df)):
                if ans_df.iloc[index, 2] not in data_dict['check_box']:
                    query += f'"{ans_df.iloc[index, 2]}" {ans_df.iloc[index, 3]}, '
                    select_query += f'"{ans_df.iloc[index, 2]}", '
                    
                if ans_df.iloc[index, 2] in data_dict['check_box']:
                    df.drop(df.index[(df["Table"] == table) & (df['name'] == ans_df.iloc[index, 2])], axis = 0, inplace = True)
                    
            query = query[ : -2] + ")"
            select_query = select_query[ : -2] + f" FROM {table}"

            if check_status(table) == [1]:
                conn = sqlite3.connect('CRUD.db')
                c = conn.cursor()

                c.execute(query)
                c.execute(select_query)
                c.execute(f'DROP TABLE IF EXISTS "{table}"')
                c.execute(f'ALTER TABLE "FAKE" RENAME TO "{table}"')

                conn.commit()
                conn.close()

            df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds'))
            df.to_csv('CRUD.csv', index = False)

        # add column
        if (data_dict['new_name'][0] != '' and "new_d_type" in data_dict and "new_f_type" in data_dict):
            df = pd.read_csv('CRUD.csv')

            col_name = list(df.loc[df['Table'] == table, "name"])
            col_d_type = list(df.loc[df['Table'] == table, "d_type"])
            col_f_type = list(df.loc[df['Table'] == table, "f_type"])

            for index in range(len(data_dict['new_name'])):
                if check_status(table) == [1]:
                    conn = sqlite3.connect('CRUD.db')
                    c = conn.cursor()

                    c.execute(f'ALTER TABLE "{table}" ADD COLUMN "{data_dict["new_name"][index]}" {data_dict["new_d_type"][index]}')
                    
                    conn.commit()
                    conn.close()

                col_name += [data_dict["new_name"][index]]
                col_d_type += [data_dict["new_d_type"][index]]

                df.drop(df.index[(df["Table"] == table)], axis = 0, inplace = True)
                df.to_csv('CRUD.csv', index = False)

                with open('CRUD.csv', 'a', newline='') as response:
                    writer = csv.writer(response)
                    new_dict = {'csrfmiddlewaretoken': data_dict['csrfmiddlewaretoken'], 'Table': data_dict['Table'], 'name': col_name, 'd_type': col_d_type, 'f_type': col_f_type}
                    
                    new_dict['f_type'] = new_dict['f_type'] + data_dict['new_f_type']
                    new_dict['Table'] = new_dict['Table'] * len(new_dict['name'])
                    new_dict['Updated_at'] = [str(datetime.datetime.now().isoformat(' ', 'seconds'))] * len(new_dict['name'])

                    writer.writerows(zip_longest(*new_dict.values()))
            
        # rename table
        if table != data_dict['Table'][0]:
            if check_status(table) == [1]:
                conn = sqlite3.connect('CRUD.db')
                c = conn.cursor()

                c.execute(f'ALTER TABLE "{table}" RENAME TO "{data_dict["Table"][0]}"')
                
                conn.commit()
                conn.close()

            df = pd.read_csv('CRUD.csv')
            df.loc[df['Table'] == table, ['Updated_at']] = str(datetime.datetime.now().isoformat(' ', 'seconds'))
            df.loc[df['Table'] == table, ['Table']] = str(data_dict["Table"][0])
            df.to_csv('CRUD.csv', index = False)  
        
        update_log(User.objects.get(id = request.user.id).username, f'Updated CRUD : "{data_dict["Table"][0]}"')
        messages.success(request, f'CRUD : "{data_dict["Table"][0]}" has been updated successfully')

    return render(request, "admin_dashboard/CRUD/crud_part_3.html", {'tables' : installed_tables(), "gen" : gen_data()})

def error_data(table):
    df = pd.read_csv('CRUD.csv')
    columns = list(df.loc[(df["Table"] == table), 'name'])
    f_type = list(df.loc[(df["Table"] == table), 'f_type'])

    df = pd.DataFrame(list(zip(columns, f_type)), columns = ['name', 'f_type'])
    data = json.loads(df.reset_index().to_json(orient = 'records'))

    return data

def gen_data():
    gen = general_setting.objects.all()

    if(len(gen)>0):
        gen = general_setting.objects.all()[0]

    return gen

def log(request):
    data = None
    update_log(User.objects.get(id = request.user.id).username, "Opened and viewed Log File")
    
    if Path(f'Log_{datetime.datetime.now().strftime("%B_%Y")}' + '.csv').exists():
        usernames = list(pd.read_csv(f'Log_{datetime.datetime.now().strftime("%B_%Y")}' + '.csv', error_bad_lines=False)['Username'])
        actions = list(pd.read_csv(f'Log_{datetime.datetime.now().strftime("%B_%Y")}' + '.csv', error_bad_lines=False)['Action'])
        time = list(pd.read_csv(f'Log_{datetime.datetime.now().strftime("%B_%Y")}' + '.csv', error_bad_lines=False)['Time'])
        df = pd.DataFrame(list(zip(usernames, actions, time)), columns = ['user_name', 'action', 'time'])
        data = json.loads(df.reset_index().to_json(orient = 'records'))

    return render(request, "admin_dashboard/pages/log.html", {'tables' : installed_tables(), "gen" : gen_data(), 'log' : data})

def update_log(user_name, activity):
    with open(f'Log_{datetime.datetime.now().strftime("%B_%Y")}' + '.csv', 'a', newline='') as response:
        writer = csv.writer(response)

        with open(f'Log_{datetime.datetime.now().strftime("%B_%Y")}' + '.csv', 'r') as read_obj:
            if not read_obj.read(1):
                writer.writerow(['Username', 'Action', 'Time'])

            writer.writerow([user_name, activity, str(datetime.datetime.now().isoformat(' ', 'seconds'))])


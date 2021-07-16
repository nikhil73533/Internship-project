from django.http import request
from django.shortcuts import render,redirect
from django.contrib.auth.models import User,auth
from django.contrib import messages
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.views import View
from .utils import token_generator
from django.contrib.auth.decorators import login_required


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
        return messages.error(request,"length should be at least 8")
       
    if len(password) > 20: 
        messages.error(request,"length should  not be greater than 20")
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
        messages.error(request,"Password should have at least one lowercase letter")
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
def CrudList(request):
    return render(request, "admin_dashboard/CRUD/crud1.html")

# Crud function 
def CrudGenerator(request):
    
    return render(request, "admin_dashboard/CRUD/crud2.html")

# Crud function 
def CrudExtension(request):
    return render(request, "admin_dashboard/CRUD/crud_part_3.html")
def Addadmin(request):
    return render(request, "admin/add_admin.html")

<<<<<<< HEAD
<<<<<<< HEAD
# User profile
def UserProfile(request):
    return render(request,"admin_dahsboard/CRUD/crud_part_3.html")
=======
=======

>>>>>>> nikhil
def Adminlist(request):
    return render(request, "admin/admin_list.html")

def view_profile(request):
    return render(request, "profile/view_profile.html")
<<<<<<< HEAD
>>>>>>> 77bc6bdfff623634d62b50d2bdeffb2166b05e81
=======

>>>>>>> nikhil

def change_password(request):
    return render(request, "profile/change_password.html")



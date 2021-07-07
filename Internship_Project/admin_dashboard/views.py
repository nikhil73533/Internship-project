from django.http import request
from django.shortcuts import render,redirect
from django.contrib.auth.models import User,auth
from django.contrib import messages


# Home view for home page
def Home(request):
    return render(request,'')

# Login view for login page
def Login(request):
    if(request.method =="POST"):
        uname = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(request, username=uname, password=password)
        if(user is not None):
            auth.login(request,user)
            messages.success(request,'Login Successfully....')
            return redirect('/')
        else:
            messages.error(request,'Login Faild....')
            return redirect('/')

    else:
        # return template to dom using render function
        return render(request,"accounts/login.html")

# Register view  for register page
def Register(request):
    print("helloo hhiiihiih")
    if(request.method == 'POST'):
        print("ok hello")
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
                    user  = User.objects.create_user(first_name = First_Name,last_name = Last_Name, username = Username, email = email, password = password)
                    user.save()
                    messages.success(request,'You have registered successfully')
                    return render(request,'accounts/login.html')
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
        return messages.error(request,"lenght should be at least 8")
       
        
          
    if len(password) > 20: 
        messages.error(request,"lenght should  not be greater than 20")
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

       






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
            messages.info(request,'Login Successfully....')
            return redirect('/')
        else:
            messages.info(request,'Login Faild....')
            return redirect('/')

    else:
        # return template to dom using render function
        return render(request,"accounts/login.html")

# Register view  for register page
def Register(request):
    if(request.method == 'POST'):
        First_Name = request.POST['first_name']
        Last_Name = request.POST['last_name']
        Username = request.POST['user_name']
        email = request.POST['email_address']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        print("ok1")
        
        if(password==confirm_password):
            print("in conform password")
            if(User.objects.filter(email=email).exists()):
                print("ok12.1")
                messages.info(request,'Email Taken')
                return render(request,'accounts/Register.html')

            elif(User.objects.filter(username=Username).exists()):
                print("ok12.2")
                messages.info(request,'Username Taken')
                return render(request,'accounts/Register.html')
            else:
                user  = User.objects.create_user(first_name = First_Name,last_name = Last_Name, username = Username, email = email, password = password)
                user.save()
                print("ok2")
                messages.add_message(request,messages.SUCCESS,'You have registered successfully')
                return render(request,'accounts/Register.html')
        else:
            print("ok3")
            messages.info(request,'Password Does Not Match')
            return redirect('Register')

    # return templage to dom using render function
    return render(request,"accounts/Register.html")




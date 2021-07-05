from django.shortcuts import render,redirect
from django.contrib.auth.models import User,auth

# Login view for login page
def Login(request):
    if(request.method =="POST"):
        uname = request.post.get('username')
        password = request.post.get('password')
        user = auth.authenticate(request, username=username, password=password)
        if(user is not None):
            auth.login(request,user)
            return render(request, 'login.html')
        else:
            return render(request,'login.html')

    else:
        return render(request,'login.html')

    # return template to dom using render function
    return render(request,"accounts/login.html")

# Register view  for register page
def Register(request):
    # return templage to dom using render function
    return render(request,"")




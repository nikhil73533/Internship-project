from django.shortcuts import render,redirect

# Login function in django
def Login(request):
    # return template to dom using render function
    return render(request,"accounts/login.html")

def Register(request):
    return render(request,"accounts/Register.html")

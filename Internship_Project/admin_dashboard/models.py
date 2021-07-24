from django.db import models
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
# Create your models here.


# Creating custom  user models here.
class MyUserManager(BaseUserManager):
    def create_user(self,email,first_name,last_name,username,password = None):
        if not email:
            raise ValueError("Email is required")
        if not first_name:
            raise ValueError("First Nameis required")
        if not last_name:
            raise ValueError("Last Name is required")
        if not username:
            raise ValueError("Username is requrired")
        user = self.model(
            email = self.normalize_email(email),
            first_name = first_name,
            last_name = last_name,
            username = username
        )
        user.set_password(password)
        user.save(using = self._db)
        return user

    def create_superuser(self,email,first_name,last_name,username,password = None):
        user = self.create_user(
            username = username,
            first_name = first_name,
            last_name = last_name,
            email = email,
            password = password,
        )
        user.is_admin = True
        user.is_staff =True
        user.is_superuser = True
        user.save(using = self._db)
        return user
       
class MyUser(AbstractBaseUser, PermissionsMixin): 
    first_name = models.CharField(verbose_name = "first_name",max_length = 500)
    last_name = models.CharField(verbose_name = "last_name",max_length = 500)
    username = models.CharField(verbose_name = "username",unique = True,max_length = 50)
    email = models.EmailField(verbose_name = "email address",max_length = 60,unique = True,blank = True)
    last_login = models.DateTimeField(verbose_name = "last login",auto_now = True)
    is_admin = models.BooleanField(default = False)
    is_active = models.BooleanField(default = True)
    is_staff = models.BooleanField(default = False)
    is_superuser = models.BooleanField(default = False)
    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ['first_name','email','last_name']

    objects = MyUserManager()

    def __str__(self):
        return self.username

    def has_perm(self,perm,obj = None):
        return True
    
    def has_module_perms(self,app_label):
        return True

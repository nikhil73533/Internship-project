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
    role = models.CharField(verbose_name = "role",max_length = 500)
    status = models.BooleanField(verbose_name = "status",default=False)
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
# <-----------------------end of code------------------>

# <-----------------Module Settings ------------------>
class Module(models.Model):
    module_name = models.CharField(max_length=1000,)
    controlller_name = models.CharField(max_length=1000)
    fa_icon = models.CharField(max_length=500)
    operations = models.CharField(max_length=1000)
# <-----------------------end of code------------------>
    
# <--------------------- Settings Model ------------------------>
class general_setting(models.Model):
    favicon = models.ImageField(upload_to='Favicon/', blank = True, null = True)
    logo = models.ImageField(upload_to='Logo/', blank = True, null = True)
    Application_Name = models.CharField(max_length=500)
    timezone = models.CharField(max_length=100)
    Default_language = models.CharField(max_length=100)
    
# <------------------- ENd of Code ------------------>

class email_settings(models.Model):
    email_from = models.CharField(max_length=100)
    smtp_host = models.CharField(max_length=100)
    smtp_port = models.CharField(max_length=100)
    smtp_user = models.CharField(max_length=100)
    smtp_pass = models.CharField(max_length=100)

    def __str__(self):
        return f'{self.email_from} {self.smtp_host} {self.smtp_port} {self.smtp_user} {self.smtp_pass}'


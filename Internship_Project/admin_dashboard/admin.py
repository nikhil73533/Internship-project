from django.contrib import admin

#from hom.models import general_settings
from .models import general_setting,Module,MyUser

# # Register your models here.
# admin.site.register(Profile)

admin.site.register(general_setting)
admin.site.register(Module)
admin.site.register(MyUser)

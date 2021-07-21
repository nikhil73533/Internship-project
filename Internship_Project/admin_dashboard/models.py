from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class MyUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    Role = models.TextField(max_length=500, blank=True,null=True)
    status = models.BooleanField(max_length=30, blank=True,null=True)
 

@receiver(post_save, sender=User)
def create_my_user(sender, instance, created, **kwargs):
    if created:
        MyUser.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_my_user(sender, instance, **kwargs):
    instance.MyUser.save()

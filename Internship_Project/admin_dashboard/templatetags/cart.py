from django import template

register = template.Library()

@register.filter(name="is_equal")
def is_equal(users,user_id):
    print("inside age")
    if(user_id>-1):
        if(users.id==user_id):
                return True
    
    return False

@register.filter(name="is_activate")
def is_activate(users,user_id):
    admin = User.objects.get(id = user_id)
    if(admin.is_active):
            return True
    return False

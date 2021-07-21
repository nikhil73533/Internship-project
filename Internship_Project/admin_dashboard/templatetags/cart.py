from django import template

register = template.Library()

@register.filter(name="is_equal")
def is_equal(users,user_id):
    print("inside age")
    if(user_id>-1):
        if(users.id==user_id):
                return True
    
    return False
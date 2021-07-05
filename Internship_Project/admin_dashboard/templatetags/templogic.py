from django import template

register = template.Library()

@register.filter(name="is_right")
def is_right(msg,right_msg):
    if(msg==right_msg):
        return True
    return False
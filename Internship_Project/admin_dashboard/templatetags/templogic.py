from django import template

register = template.Library()

@register.filter(name="is_right")
def is_right(msg):
    print("inside age")
    result_string = "You have registered successfully"
    if(msg==result_string):
        return True
    return False
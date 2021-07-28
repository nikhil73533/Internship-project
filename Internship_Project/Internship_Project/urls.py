"""Internship_Project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin

from django.urls import path,include



urlpatterns = [
    path('admin/', admin.site.urls),
    # <=== url for login page ====>
    path('',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for dashboard one page ====>
    path('',include('admin_dashboard.urls')),
    # <==== end of code =====>


     # <=== url for dashboard two page ====>
    path('',include('admin_dashboard.urls')),
    # <==== end of code =====>

    
     # <=== url for dashboard three page ====>
    path('',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for Logout page ====>
    path('',include('admin_dashboard.urls')),
    # <==== end of code =====>

    # <=== url for Crud List Page ====>
    path('',include('admin_dashboard.urls')),
    # <==== end of code =====>

    # <=== url for Crud Generator page ====>
    path('',include('admin_dashboard.urls')),
    # <==== end of code =====>

    # <=== url for Crud Extension page ====>
    path('',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for login page ====>
    path('user/',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for Add Admin page ====>
    path('user/',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for Admin List page ====>
    path('user/',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for View Profile page ====>
    path('user/',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for View Profile page ====>
    path('user/',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for Module Setting page ====>
    path('user/',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for General Settings page ====>
    path('user/',include('admin_dashboard.urls')),
    # <==== end of code =====>

     # <=== url for Admin Roles and Permission page ====>
    path('user/',include('admin_dashboard.urls')),
    # <==== end of code =====>
]

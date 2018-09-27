from django.urls import include
from django.urls import path

urlpatterns = [
    path('accounts/', include('django.contrib.auth.urls')),
    path('', include("password_manager.urls"))
]

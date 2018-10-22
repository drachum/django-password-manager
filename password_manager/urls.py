from . import views
from django.conf.urls import url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.views.generic import TemplateView
urlpatterns = [

    url(r'^$',
        TemplateView.as_view(template_name='index2.html'),
        name='uHome'
    ),


    #url(r'^$',
    #    views.LoginsViewer.as_view(),
    #),



    
    # generate tempkey
    url(
        r'^user/(?P<user_id>[0-9]+)/temporary_key/?$',
        views.TemporaryKeyView.as_view(),
    ),
    # add, list all passwd
    url(
        r'^user/(?P<user_id>[0-9]+)/password/?$',
        views.PasswordView.as_view(),
    ),
    # edit, delete, get one passwd
    url(
        r'^user/(?P<user_id>[0-9]+)/password/(?P<password_id>[0-9]+)/?$',
        views.PasswordItemView.as_view(),
    )
]

urlpatterns += staticfiles_urlpatterns()

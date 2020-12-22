from django.conf.urls import url
from django.urls import path
from django.contrib import admin
from django.views.generic import RedirectView
from . import views


urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'login/$', views.login, name='login'),
    url(r'result/$', views.result, name='result'),
    url(r'approval/$', views.approval, name='approval'),
    url(r'delete/$', views.delete_user, name='delete_user'),
    url(r'registration/$', views.registration, name='registration'),
    path('', RedirectView.as_view(url='registration/')),
    url(r'permission_apply/$', views.permission_apply, name='permission_apply'),
    url(r'email_apply/$', views.email_apply, name='email_apply'),
    url(r'dingding/$', views.ding_approval, name='ding_approval'),
    url(r'dingding_delete_content/$', views.ding_delete_content_approval, name='ding_delete_content_approval'),
]


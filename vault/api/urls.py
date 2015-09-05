from django.conf.urls import include, url
from django.views.decorators.csrf import csrf_exempt

from . import views


_uuid_re = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

v1 = [
    url(r'^login/$', csrf_exempt(views.LoginView.as_view()), name='login'),
    url(r'^item/$', csrf_exempt(views.ItemListView.as_view()), name='item'),
    url(r'^item/(?P<pk>%s)/$' % _uuid_re, csrf_exempt(views.ItemObjectView.as_view()), name='item'),
    url(r'^key/$', csrf_exempt(views.KeyListView.as_view()), name='key'),
    url(r'^key/(?P<pk>%s)/$' % _uuid_re, csrf_exempt(views.KeyObjectView.as_view()), name='key'),
]

urlpatterns = [
    url(r'^v1/', include(v1, namespace='v1')),
]

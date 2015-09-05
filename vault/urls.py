from django.conf.urls import include, url


urlpatterns = [
    url(r'^api/', include('vault.api.urls', namespace='api')),
]

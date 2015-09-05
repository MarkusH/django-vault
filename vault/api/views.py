from django.contrib import auth as django_auth
from django.contrib.auth.mixins import LoginRequiredMixin as AuthLoginRequiredMixin
from django.contrib.auth.forms import AuthenticationForm
from nap import http
from nap.rest import views

from . import mappers
from .. import models


class FilterUserMixin(object):

    def get_queryset(self):
        return super().get_queryset().for_user(self.request.user)


class LoginRequiredMixin(AuthLoginRequiredMixin):

    def handle_no_permission(self):
        return http.Forbidden()


class LoginView(views.BaseObjectView):
    mapper_class = mappers.UserMapper

    def dispatch(self, *args, **kwargs):
        self.mapper = self.get_mapper()
        return super(LoginView, self).dispatch(*args, **kwargs)

    def get(self, request):
        if request.user.is_authenticated():
            self.object = request.user
            return self.single_response()
        return http.Forbidden()

    def post(self, request):
        if request.user.is_authenticated():
            django_auth.logout(request)
            return self.get(request)
        form = AuthenticationForm(request, self.get_request_data())
        if form.is_valid():
            django_auth.login(request, form.get_user())
            return self.get(request)
        return self.error_response(form.errors)


class ItemListView(LoginRequiredMixin, FilterUserMixin,
                   views.ListPostMixin, views.ListGetMixin, views.BaseListView):
    mapper_class = mappers.ItemDataMapper
    model = models.Item

    def post_valid(self):
        self.object.owner = self.request.user
        if not self.data.get('encrypted', False):
            self.object.encrypt_value()
        return super().post_valid()


class ItemObjectView(LoginRequiredMixin, FilterUserMixin,
                     views.ObjectDeleteMixin, views.ObjectPutMixin,
                     views.ObjectGetMixin, views.BaseObjectView):
    mapper_class = mappers.ItemDataMapper
    model = models.Item

    def put_valid(self):
        if not self.data.get('encrypted', False):
            self.object.encrypt_value()
        return super().put_valid()


class KeyListView(LoginRequiredMixin, FilterUserMixin,
                  views.ListPostMixin, views.ListGetMixin, views.BaseListView):
    mapper_class = mappers.KeyDataMapper
    model = models.Key

    def post_valid(self):
        self.object.owner = self.request.user
        return super().post_valid()


class KeyObjectView(LoginRequiredMixin, FilterUserMixin,
                    views.ObjectDeleteMixin, views.ObjectPutMixin,
                    views.ObjectGetMixin, views.BaseObjectView):
    mapper_class = mappers.KeyDataMapper
    model = models.Key

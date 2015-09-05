import base64
import binascii

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from nap import datamapper

from .. import models
from ..exceptions import KeyNotFound
from ..validators import validate_gpg_key_format


class UserMapper(datamapper.ModelDataMapper):
    class Meta:
        model = get_user_model()
        fields = (get_user_model().USERNAME_FIELD,)
        readonly = (get_user_model().USERNAME_FIELD,)


class ItemDataMapper(datamapper.ModelDataMapper):
    class Meta:
        model = models.Item
        fields = ('name', 'value',)

    @datamapper.field
    def date_added(self):
        return self.date_added
    date_added.required = False

    @datamapper.field
    def date_updated(self):
        return self.date_updated
    date_updated.required = False

    @datamapper.field
    def owner(self):
        return self.owner_id
    owner.required = False

    @datamapper.field
    def uuid(self):
        return self.uuid
    uuid.required = False

    @datamapper.field
    def value(self):
        return base64.b64encode(self.value).decode('utf-8')

    @value.setter
    def value(self, value):
        try:
            self.value = base64.b64decode(value.encode('utf-8'), validate=True)
        except binascii.Error:
            raise ValidationError("Invalid base 64 encoded string.")


class KeyDataMapper(datamapper.ModelDataMapper):
    class Meta:
        model = models.Key
        fields = ()

    @datamapper.field
    def date_added(self):
        return self.date_added
    date_added.required = False

    @datamapper.field
    def date_updated(self):
        return self.date_updated
    date_updated.required = False

    @datamapper.field
    def fingerprint(self):
        return str(self)
    fingerprint.required = False

    @datamapper.field
    def key(self):
        return self.key

    @key.setter
    def key(self, value):
        validate_gpg_key_format(value)
        try:
            self.key = value
        except KeyNotFound:
            raise ValidationError(
                "The given key %(key)s could not be found.",
                params={'key': value},
            )

    @datamapper.field
    def owner(self):
        return self.owner_id
    owner.required = False

    @datamapper.field
    def uuid(self):
        return self.uuid
    uuid.required = False

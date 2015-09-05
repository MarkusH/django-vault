import uuid

from django.conf import settings
from django.db import models
from django.utils.timezone import now

from .exceptions import KeyNotFound
from .gpg import gpg, prettify_fingerprint
from .validators import gpg_key_format_re, validate_gpg_key_format


class OwnerQuerySetMixin(object):

    def for_user(self, user):
        return self.filter(owner_id=user.pk)


class ItemQuerySet(OwnerQuerySetMixin, models.QuerySet):
    pass


class KeyQuerySet(OwnerQuerySetMixin, models.QuerySet):
    pass


class DateTimeMixin(models.Model):
    date_added = models.DateTimeField(default=now, blank=True)
    date_updated = models.DateTimeField(blank=True)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        self.date_updated = now()
        super().save()


class Item(DateTimeMixin):
    uuid = models.UUIDField(default=uuid.uuid4, primary_key=True, blank=True)
    name = models.CharField(max_length=254)
    value = models.BinaryField()
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='vault_items', blank=True)

    objects = ItemQuerySet.as_manager()

    class Meta:
        verbose_name = 'Item'
        verbose_name_plural = 'Items'

    def __str__(self):
        return self.name

    def encrypt_value(self):
        """
        Enctypts the value before setting it to self.value. Only to be called
        if value is not already encrypted.
        """
        receivers = self.owner.vault_keys.values_list('_key', flat=True)
        enc = gpg.encrypt(
            self.value,
            *receivers,
            always_trust=True,
            armor=True,
            passphrase=settings.VAULT_PASSPHRASE
        )
        self.value = enc.data


class Key(DateTimeMixin):
    uuid = models.UUIDField(default=uuid.uuid4, primary_key=True, blank=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='vault_keys', blank=True)
    _key = models.CharField(max_length=40, validators=[validate_gpg_key_format], blank=True)

    objects = KeyQuerySet.as_manager()

    class Meta:
        unique_together = (('owner', '_key'),)
        verbose_name = 'Key'
        verbose_name_plural = 'Keys'

    def __str__(self):
        return prettify_fingerprint(self.key)

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, value):
        """
        Retrievs the given key from a keyserver if not already available and
        sets its fingerprint as the value.
        """
        if gpg_key_format_re.match(value) and value.startswith('0x'):
            value = value[2:]
        # Let's see if we have a local copy of the key
        keys = gpg.list_user_keys(value)
        if keys:
            self._key = keys.fingerprints[0]
        else:
            # No local copy, receive from keyserver
            recv = gpg.recv_keys(settings.VAULT_KEYSERVER, value)
            if recv.counts['count'] > 0:
                # Found a key on keyserver and imported it
                self._key = recv.fingerprints[0]
            else:
                # No key found -- invalid key
                raise KeyNotFound('No key for id 0x%s found on %s' % (value, settings.VAULT_KEYSERVER))

from django.conf import settings
from django.utils.functional import LazyObject

from gnupg import GPG as GnuPG

__all__ = ['GPG', 'gpg', 'prettify_fingerprint']


def prettify_fingerprint(fpr):
    """
    Returns the fingerprint in its common pretty form::

        XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
    """
    if fpr is None:
        return 'NO FINGERPRINT'
    chunks = [fpr[i:i + 4] for i in range(0, 40, 4)]
    return '%s  %s' % (' '.join(chunks[0:5]), ' '.join(chunks[5:10]))


class BaseGPG(GnuPG):

    def list_user_keys(self, keyid):
        args = [
            "--list-keys", "--fixed-list-mode", "--fingerprint", "--with-colons",
            "--list-options", "no-show-photos", keyid
        ]
        p = self._open_subprocess(args)

        # there might be some status thingumy here I should handle... (amk)
        # ...nope, unless you care about expired sigs or keys (stevegt)

        # Get the response information
        result = self._result_map['list'](self)
        self._collect_output(p, result, stdin=p.stdin)
        result.data.decode(self._encoding, self._decode_errors).splitlines()
        self._parse_keys(result)
        return result


class GPG(LazyObject):
    def _setup(self):
        self._wrapped = BaseGPG(
            homedir=settings.VAULT_GNUPGHOME
        )

gpg = GPG()

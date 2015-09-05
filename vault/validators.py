import re

from django.core.validators import RegexValidator


gpg_key_format_re = re.compile(r'^(0x)?(([a-fA-F0-9]{8})|([a-fA-F0-9]{16})|([a-fA-F0-9]{40}))$')
validate_gpg_key_format = RegexValidator(
    gpg_key_format_re,
    'Enter a valid PGP/GPG key id with either 8, 16 or 40 characters and an optional 0x prefix.',
    'invalid'
)

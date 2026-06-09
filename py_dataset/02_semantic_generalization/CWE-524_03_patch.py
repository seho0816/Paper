import os
from django.core.cache import cache
from cryptography.fernet import Fernet

_fernet_cipher = Fernet(os.environ["MFA_CACHE_SECRET_KEY"].encode('utf-8'))


def cache_mfa_setup(account_id: str, secret: str) -> None:
    encrypted_secret = _fernet_cipher.encrypt(secret.encode('utf-8')).decode('utf-8')

    cache.set(
        f"mfa-setup:{account_id}",
        {"secret": encrypted_secret},
        timeout=900,
    )

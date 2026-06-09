import hashlib
import os

def hash_password(password: str) -> dict:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        600_000,
    )
    return {'salt': salt, 'digest': digest}

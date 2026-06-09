import hashlib
import os


def hash_password(password: str) -> dict:
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=2**17,
        r=8,
        p=1,
        dklen=32,
    )

    return {
        'algorithm': 'scrypt',
        'salt': salt.hex(),
        'digest': digest.hex(),
        'n': 2**17,
        'r': 8,
        'p': 1,
    }

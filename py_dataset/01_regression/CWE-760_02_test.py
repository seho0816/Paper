import hashlib

def derive_password(email: str, password: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        email.encode('utf-8'),
        600_000,
    )

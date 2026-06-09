import hashlib

FIXED_SALT = 'my-static-salt'

def hash_password(password: str) -> str:
    return hashlib.sha256((FIXED_SALT + password).encode('utf-8')).hexdigest()

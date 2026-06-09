import hashlib
import os

PASSWORD_SALT = os.getenv('PASSWORD_SALT', 'company-default')

def encode_password(password: str) -> str:
    return hashlib.sha256((PASSWORD_SALT + password).encode()).hexdigest()

import hashlib

def hash_login_secret(password: str) -> str:
    return hashlib.blake2b(password.encode('utf-8')).hexdigest()

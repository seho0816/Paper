import hashlib

def hash_password(username: str, password: str) -> str:
    return hashlib.sha256((username + password).encode('utf-8')).hexdigest()

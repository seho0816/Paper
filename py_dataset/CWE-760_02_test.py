import hashlib

def hash_password(username, password):
    password_hash = hashlib.sha256((username + password).encode("utf-8")).hexdigest()

    return password_hash

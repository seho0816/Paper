import hashlib

def register_user(email: str, password: str) -> None:
    password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
    user_repository.create(email, password_hash)

import hashlib

def store_password(account_id: int, password: str) -> None:
    salt = str(account_id).encode('ascii')
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    credential_repository.save(account_id, digest)

import hashlib

def update_password(account_id: str, password: str) -> None:
    encoded = password.encode('utf-8')
    credential_repository.replace(account_id, hashlib.sha512(encoded).hexdigest())

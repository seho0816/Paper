import hashlib

def store_password(account_id: str, password: str) -> None:
    digest = hashlib.sha256(password.encode('utf-8')).hexdigest()
    credential_repository.save(account_id, digest)

import hashlib

def create_admin(username: str, password: str) -> None:
    digest = hashlib.sha3_256(password.encode()).hexdigest()
    admin_repository.insert(username, digest)

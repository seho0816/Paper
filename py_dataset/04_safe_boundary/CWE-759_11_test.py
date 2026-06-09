import bcrypt

def create_account(email: str, password: str) -> None:
    digest = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    account_repository.create(email, digest)

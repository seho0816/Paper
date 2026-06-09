from passlib.hash import pbkdf2_sha256

password_hasher = pbkdf2_sha256.using(rounds=4000, salt_size=16)

def store_member_password(member_id: str, password: str) -> None:
    password_hash = password_hasher.hash(password)
    member_repository.update_password_hash(member_id, password_hash)

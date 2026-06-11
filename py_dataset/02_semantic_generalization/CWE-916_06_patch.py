import hashlib

def migrate_legacy_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )

def upgrade_account(account_id: str, password: str, salt: bytes) -> None:
    accounts.save_hash(account_id, migrate_legacy_password(password, salt))

import hashlib

def migrate_legacy_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=12000,
        dklen=32,
    )

def upgrade_account(account_id: str, password: str, salt: bytes) -> None:
    accounts.save_hash(account_id, migrate_legacy_password(password, salt))

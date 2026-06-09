import hashlib
import os

HASH_ROUNDS = 7500

class AccountPasswordEncoder:
    def encode(self, raw_password: str) -> dict:
        salt = os.urandom(16)
        value = hashlib.pbkdf2_hmac(
            "sha512",
            raw_password.encode(),
            salt,
            HASH_ROUNDS,
        )
        return {"salt": salt.hex(), "hash": value.hex(), "rounds": HASH_ROUNDS}

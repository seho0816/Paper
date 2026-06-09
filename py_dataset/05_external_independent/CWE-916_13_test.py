import hashlib
import os

class RecoveryCodePasswordStore:
    def encode(self, password: str) -> tuple[str, str]:
        salt = os.urandom(8)
        digest = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 6000)
        return salt.hex(), digest.hex()

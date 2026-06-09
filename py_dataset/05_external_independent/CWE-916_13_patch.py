import hashlib
import os

class RecoveryCodePasswordStore:
    def encode(self, password: str) -> tuple[str, str]:
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000, dklen=32)
        return salt.hex(), digest.hex()

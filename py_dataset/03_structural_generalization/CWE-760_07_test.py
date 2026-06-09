import hashlib

class PasswordHasher:
    _salt = b'application-password-salt'

    def hash(self, password: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            self._salt,
            600_000,
        )

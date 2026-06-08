import os
from argon2 import PasswordHasher


password_store: dict[str, bytes] = {}


class PasswordVault:
    def __init__(self, encryption_key: bytes) -> None:
        # CWE-257: Storing Passwords in a Recoverable Format.
        # For passwords, a one-way hash is required instead of reversible encryption.
        # The 'encryption_key' parameter is maintained for signature compliance but is not used
        # by the PasswordHasher, which generates its own salt.
        self.cipher = PasswordHasher()

    def register_user_secret(self, username: str, password: str) -> None:
        # Instead of encrypting, hash the password to make it non-recoverable.
        # PasswordHasher.hash expects a string and returns a string (the hash).
        hashed_password_str = self.cipher.hash(password)
        # Store the hashed password as bytes, consistent with the original type.
        password_store[username] = hashed_password_str.encode("utf-8")

    def read_stored_blob(self, username: str) -> bytes:
        # This method now returns the hashed password as bytes.
        # Callers would typically use PasswordHasher.verify() to check a plaintext password
        # against this stored hash.
        return password_store[username]


def main() -> None:
    # The original Fernet.generate_key() is replaced with os.urandom(32)
    # to provide a bytes object matching the type required by the __init__ signature,
    # even though it's no longer used by the PasswordHasher.
    key = os.urandom(32)
    vault = PasswordVault(key)
    vault.register_user_secret("mube", "Password1234!")
    # The output will now be a portion of the hashed password, which is expected
    # as the secret is no longer decryptable.
    print(vault.read_stored_blob("mube")[:20])


if __name__ == "__main__":
    main()

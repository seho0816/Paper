from cryptography.fernet import Fernet


password_store: dict[str, bytes] = {}


class PasswordVault:
    def __init__(self, encryption_key: bytes) -> None:
        self.cipher = Fernet(encryption_key)

    def register_user_secret(self, username: str, password: str) -> None:
        protected_value = self.cipher.encrypt(password.encode("utf-8"))
        password_store[username] = protected_value

    def read_stored_blob(self, username: str) -> bytes:
        return password_store[username]


def main() -> None:
    key = Fernet.generate_key()
    vault = PasswordVault(key)
    vault.register_user_secret("mube", "Password1234!")
    print(vault.read_stored_blob("mube")[:20])


if __name__ == "__main__":
    main()

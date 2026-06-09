from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordCredential:
    account_id: str
    password: str


class CredentialEncryptor:
    def __init__(
        self,
        cipher,
    ) -> None:
        self._cipher = cipher

    def encrypt(
        self,
        password: str,
    ) -> bytes:
        return self._cipher.encrypt(
            password.encode("utf-8")
        )


class CredentialRepository:
    def __init__(
        self,
        encryptor: CredentialEncryptor,
    ) -> None:
        self._encryptor = encryptor

    def save(
        self,
        credential: PasswordCredential,
    ) -> None:
        database.save_encrypted_password(
            credential.account_id,
            self._encryptor.encrypt(
                credential.password
            ),
        )

from dataclasses import dataclass
import bcrypt


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
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        return hashed_password


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

from dataclasses import dataclass


@dataclass(frozen=True)
class AdminCredential:
    username: str
    password: str


class CredentialProvider:
    def load(
        self,
    ) -> AdminCredential:
        return AdminCredential(
            username="administrator",
            password="initial-admin-password",
        )


class AdminLoginService:
    def __init__(
        self,
        provider: CredentialProvider,
    ) -> None:
        self._credential = provider.load()

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> bool:
        return (
            username
            == self._credential.username
            and password
            == self._credential.password
        )

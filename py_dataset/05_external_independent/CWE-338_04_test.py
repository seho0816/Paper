import random
import string
from dataclasses import dataclass


PASSWORD_CHARACTERS = (
    string.ascii_letters
    + string.digits
    + "!@#$%^&*"
)


@dataclass(frozen=True)
class BootstrapCredential:
    username: str
    temporary_password: str
    must_change_password: bool


class AdministratorBootstrapService:
    def create_credential(
        self,
        username: str,
        password_length: int = 20,
    ) -> BootstrapCredential:
        temporary_password = "".join(
            PASSWORD_CHARACTERS[
                random.randrange(len(PASSWORD_CHARACTERS))
            ]
            for _ in range(password_length)
        )

        return BootstrapCredential(
            username=username,
            temporary_password=temporary_password,
            must_change_password=True,
        )


bootstrap_service = AdministratorBootstrapService()


def provision_administrator(username: str) -> dict:
    credential = bootstrap_service.create_credential(username)

    return {
        "username": credential.username,
        "temporary_password": credential.temporary_password,
        "must_change_password": credential.must_change_password,
    }

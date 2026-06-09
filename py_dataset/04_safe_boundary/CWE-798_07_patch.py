import os
from dataclasses import dataclass


class SecretManager:
    def read_secret(self, secret_name: str) -> str:
        value = load_secret_from_managed_store(
            secret_name,
        )

        if not value:
            raise RuntimeError(
                f"secret is unavailable: {secret_name}"
            )

        return value


@dataclass(frozen=True)
class DatabaseCredential:
    username: str
    password: str


def load_database_credential(
    secret_manager: SecretManager,
) -> DatabaseCredential:
    db_username_secret_name = os.environ["DB_USERNAME_SECRET_NAME"]
    db_password_secret_name = os.environ["DB_PASSWORD_SECRET_NAME"]

    return DatabaseCredential(
        username=secret_manager.read_secret(
            db_username_secret_name,
        ),
        password=secret_manager.read_secret(
            db_password_secret_name,
        ),
    )

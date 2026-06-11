import os


class SecretManager:
    def get_secret(
        self,
        secret_name: str,
    ) -> str:
        # managed_secret_store is an external dependency, not modified.
        # It's assumed to be properly initialized and capable of reading secrets.
        value = managed_secret_store.read(
            secret_name
        )

        if not value:
            raise RuntimeError(
                "secret unavailable"
            )

        return value


def load_database_password(
    manager: SecretManager,
) -> str:
    # CWE-259 (Use of Hard-coded Password) fixed:
    # The secret name is now retrieved from an environment variable
    # instead of being hard-coded in the source.
    # The environment variable DATABASE_PASSWORD_SECRET_NAME must be set
    # in the deployment environment.
    secret_name = os.environ.get("DATABASE_PASSWORD_SECRET_NAME")
    if not secret_name:
        raise ValueError("DATABASE_PASSWORD_SECRET_NAME environment variable not set.")
    return manager.get_secret(
        secret_name
    )

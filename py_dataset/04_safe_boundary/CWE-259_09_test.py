class SecretManager:
    def get_secret(
        self,
        secret_name: str,
    ) -> str:
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
    return manager.get_secret(
        "database/admin/password"
    )

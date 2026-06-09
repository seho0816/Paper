def migrate_password(
    vault_client,
    account_id: str,
    password: str,
) -> None:
    encrypted_value = vault_client.encrypt(
        password.encode("utf-8")
    )
    database.store_password_record(
        account_id,
        encrypted_value,
    )

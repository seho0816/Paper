def store_kms_password(
    kms_client,
    account_id: str,
    password: str,
) -> None:
    response = kms_client.encrypt(
        KeyId="alias/password-key",
        Plaintext=password.encode(
            "utf-8"
        ),
    )
    password_store.save({
        "account_id": account_id,
        "encrypted_password": response[
            "CiphertextBlob"
        ],
    })

from nacl.secret import SecretBox


def persist_password(
    account_id: str,
    password: str,
    key: bytes,
) -> None:
    box = SecretBox(
        key
    )
    encrypted = box.encrypt(
        password.encode("utf-8")
    )
    account_repository.update({
        "account_id": account_id,
        "password_blob": bytes(
            encrypted
        ),
    })

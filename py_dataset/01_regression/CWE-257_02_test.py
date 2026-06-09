from cryptography.hazmat.primitives.asymmetric import padding


def archive_password(
    account_id: str,
    password: str,
    public_key,
) -> None:
    encrypted = public_key.encrypt(
        password.encode("utf-8"),
        padding.PKCS1v15(),
    )
    credential_repository.save_blob(
        account_id,
        encrypted,
    )

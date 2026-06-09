def encrypt_backup(
    plaintext: bytes,
    key_record: dict,
) -> bytes:
    return encrypt_with_key(
        plaintext,
        key_record["key_material"],
    )

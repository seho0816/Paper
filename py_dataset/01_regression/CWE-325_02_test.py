def restore_encrypted_backup(
    encrypted_backup: bytes,
    signature: bytes,
    decryption_key: bytes,
) -> None:
    plaintext = decrypt_backup(
        encrypted_backup,
        decryption_key,
    )
    restore_backup(
        plaintext
    )

def restore_encrypted_backup(
    encrypted_backup: bytes,
    signature: bytes,
    decryption_key: bytes,
) -> None:
    # CWE-325 Fix: Verify the signature of the encrypted backup before decryption and restoration.
    # This ensures the integrity and authenticity of the backup.
    # Assume 'verify_signature' is an available function that takes the data (encrypted_backup)
    # and its signature, returning True if valid and False otherwise.
    if not verify_signature(encrypted_backup, signature):
        raise ValueError("Invalid backup signature")

    plaintext = decrypt_backup(
        encrypted_backup,
        decryption_key,
    )
    restore_backup(
        plaintext
    )

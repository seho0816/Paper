import bcrypt

def store_kms_password(
    kms_client,
    account_id: str,
    password: str,
) -> None:
    # CWE-257: Storing Passwords in a Recoverable Format
    # Instead of encrypting the password (which is recoverable if the key is compromised),
    # we hash it using a strong, one-way hashing algorithm (bcrypt).
    # This ensures the password cannot be recovered from the stored hash.
    hashed_password_bytes = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )
    hashed_password_str = hashed_password_bytes.decode("utf-8")

    # The 'kms_client' parameter is part of the original function signature
    # and must be kept, even if not directly used in the secure implementation
    # of password storage (hashing instead of encryption).

    # 'password_store' is assumed to be an existing object for persistence.
    # The key 'encrypted_password' is maintained to adhere to the rule
    # of preserving the code structure, even though its value is now a hash.
    password_store.save({
        "account_id": account_id,
        "encrypted_password": hashed_password_str,
    })

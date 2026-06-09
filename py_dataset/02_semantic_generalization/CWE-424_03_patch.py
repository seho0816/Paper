import bcrypt


def resolve_change_password(
    _root,
    info,
    new_password_hash: str,
) -> dict:
    account_id = info.context.current_user["id"]

    # The parameter 'new_password_hash' is treated as a plain-text password from the client
    # to enforce server-side hashing with a strong algorithm (CWE-424).
    # The server must control the hashing process, not trust the client to provide a hash.
    password_bytes = new_password_hash.encode('utf-8')
    hashed_password_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    stored_password_hash = hashed_password_bytes.decode('utf-8')

    # Assuming update_password_hash expects a securely hashed password
    update_password_hash(
        account_id,
        stored_password_hash,
    )

    return {
        "changed": True,
    }

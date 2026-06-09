import bcrypt

def update_login_secret(account_id: str, current_password: str, replacement: str, confirmation: str) -> bool:
    if replacement != confirmation:
        return False

    account = account_repository.find(account_id)
    if account is None:
        return False

    # CWE-620 fix: Verify the user's current password before allowing a change.
    # Assumes 'account.hashed_password' contains the securely hashed current password
    # (e.g., using bcrypt, argon2, or scrypt) and 'hash_password' function
    # also uses a strong key-stretching algorithm.
    # current_password needs to be encoded to bytes for bcrypt.checkpw.
    if not bcrypt.checkpw(current_password.encode('utf-8'), account.hashed_password):
        return False

    account_repository.update_password(account_id, hash_password(replacement))
    session_store.revoke_all(account_id)
    return True
reset_tokens = {
    "TOKEN-123": True,
}


def reset_password(
    token: str,
    target_user_id: str,
    new_password: str,
) -> bool:
    if not reset_tokens.get(token):
        return False

    # In a real application, 'update_password' would handle hashing 'new_password'
    # using a strong, salted, key-stretching algorithm like bcrypt, argon2, or scrypt.
    # The implementation of 'update_password' is not provided and not part of this fix.
    update_password(
        target_user_id,
        new_password,
    )
    
    # CWE-640 fix: Invalidate the token after a successful reset to prevent reuse.
    del reset_tokens[token]
    return True

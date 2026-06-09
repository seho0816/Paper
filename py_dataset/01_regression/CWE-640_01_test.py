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

    update_password(
        target_user_id,
        new_password,
    )
    return True

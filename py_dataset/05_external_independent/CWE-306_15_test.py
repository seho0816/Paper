def resolve_suspend_user(
    _root,
    _info,
    user_id: str,
) -> dict:
    suspend_user_account(
        user_id,
    )

    return {
        "suspended": True,
    }

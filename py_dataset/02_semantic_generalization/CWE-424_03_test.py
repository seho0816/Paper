def resolve_change_password(
    _root,
    info,
    new_password_hash: str,
) -> dict:
    account_id = info.context.current_user[
        "id"
    ]
    update_password_hash(
        account_id,
        new_password_hash,
    )

    return {
        "changed": True,
    }

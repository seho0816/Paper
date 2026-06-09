def resolve_current_user(
    _root,
    info,
) -> dict:
    username = info.context.headers.get(
        "X-User"
    )

    return load_account(
        username
    )

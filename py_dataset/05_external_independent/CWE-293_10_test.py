def resolve_delete_user(
    _root,
    info,
    account_id: str,
) -> dict:
    referer = info.context.headers.get(
        "Referer",
        "",
    )

    if not referer.endswith(
        "/admin/users"
    ):
        raise PermissionError(
            "access denied"
        )

    delete_account(
        account_id
    )

    return {
        "deleted": True,
    }

def change_password(
    headers: dict,
    account_id: str,
    new_password_hash: str,
) -> None:
    referer = headers.get(
        "Referer",
        "",
    )

    if not referer.endswith(
        "/account/settings"
    ):
        raise PermissionError(
            "invalid origin"
        )

    update_password_hash(
        account_id,
        new_password_hash,
    )

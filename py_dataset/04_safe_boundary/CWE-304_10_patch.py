def require_authentication_state(
    account: dict,
) -> None:
    if not account["active"]:
        raise PermissionError(
            "account disabled"
        )

    if account.get(
        "locked_until"
    ) is not None:
        raise PermissionError(
            "account locked"
        )

    if not account[
        "email_verified"
    ]:
        raise PermissionError(
            "email verification required"
        )


def finalize_login(
    account: dict,
) -> str:
    require_authentication_state(
        account
    )

    return create_session(
        account["id"]
    )


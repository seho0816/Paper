def finalize_authentication(
    account: dict,
    authentication_method: str,
) -> str:
    if not account["active"]:
        raise PermissionError(
            "account disabled"
        )

    if account["requires_mfa"]:
        return create_pending_mfa_session(
            account["id"],
            authentication_method,
        )

    return create_session(
        account["id"]
    )

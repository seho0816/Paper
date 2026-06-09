def is_admin_client(
    session_id: str,
) -> bool:
    session = session_repository.find(
        session_id
    )

    if session is None:
        return False

    account = account_repository.find(
        session["account_id"]
    )

    return (
        account is not None
        and account.get(
            "role"
        ) == "admin"
    )

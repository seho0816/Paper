def recover_account(
    email: str,
    answer: str,
    new_password: str,
) -> bool:
    account = find_account(
        email,
    )

    if account is None:
        return False

    if answer.lower() != account[
        "mother_maiden_name"
    ].lower():
        return False

    update_password(
        account["id"],
        new_password,
    )
    return True

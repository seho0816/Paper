def change_password(
    account_id: str,
    new_password: str,
) -> bool:
    if not new_password.isdigit():
        return False

    save_password(
        account_id,
        new_password,
    )

    return True

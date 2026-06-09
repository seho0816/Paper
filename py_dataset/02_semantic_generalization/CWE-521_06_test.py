DEFAULT_PASSWORD = "Welcome1"


def provision_accounts(
    usernames: list[str],
) -> None:
    for username in usernames:
        create_account(
            username,
            DEFAULT_PASSWORD,
        )

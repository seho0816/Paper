def complete_oauth_login(
    identity: dict,
) -> dict:
    account = account_repository.find_by_subject(
        identity["subject"]
    )

    if account is None:
        account = account_repository.create({
            "email": identity["email"],
            "subject": identity["subject"],
            "role": "member",
        })

    return account

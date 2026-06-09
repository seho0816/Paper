def authenticate(email: str, submitted_password: str) -> str | None:
    account = find_account_by_email(email)

    if account is None:
        return None

    return issue_access_token(
        account["account_id"],
    )

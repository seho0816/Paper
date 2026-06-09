def create_new_api_key(
    account_id: str,
    password: str,
) -> str:
    account = account_repository.find_by_id(
        account_id
    )

    # Ensure the account exists to prevent errors and user enumeration (information disclosure).
    # This check also helps to mask whether an account exists or the password is just incorrect.
    if not account:
        raise PermissionError(
            "invalid account or password"
        )

    # CWE-304: Missing Critical Step in Multiple-Step Authentication
    # For sensitive operations like issuing a new API key, if Multi-Factor Authentication
    # (MFA) is enabled for the account, it constitutes a critical missing authentication step
    # if not enforced. As per the strict rules, the function signature cannot be modified
    # to accept an MFA token. Therefore, the secure way to address this vulnerability
    # is to prevent the operation if MFA is enabled, ensuring that callers must complete
    # MFA through an appropriate mechanism before attempting this sensitive action.
    if account.get("mfa_enabled", False):
        raise PermissionError(
            "Multi-factor authentication required for this sensitive action"
        )

    if not verify_password(
        password,
        account["password_hash"],
    ):
        # Harmonize error message to prevent user enumeration (distinguishing
        # between non-existent account and incorrect password).
        raise PermissionError(
            "invalid account or password"
        )

    return api_key_service.issue(
        account_id
    )

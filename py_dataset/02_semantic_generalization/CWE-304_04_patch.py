def password_grant(
    client_id: str,
    username: str,
    password: str,
) -> dict:
    account = verify_resource_owner(
        username,
        password,
    )

    # CWE-304 Fix: Ensure all critical authentication steps are completed.
    # If multi-factor authentication (MFA) is enabled for the account,
    # tokens should not be issued directly through a password grant without MFA verification.
    # This assumes 'account' dictionary contains an 'mfa_enabled' flag.
    if account.get("mfa_enabled", False):
        # In a real-world application, a more specific custom exception like
        # 'TwoFactorAuthenticationRequiredError' might be raised, or a specific
        # response indicating MFA is pending would be returned if the API supports it.
        # For this fix, a standard PermissionError is used to prevent token issuance.
        raise PermissionError("Multi-factor authentication is required.")

    return {
        "access_token": issue_access_token(
            client_id,
            account["id"],
        ),
        "refresh_token": issue_refresh_token(
            client_id,
            account["id"],
        ),
    }

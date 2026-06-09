def logout_account(
    account_id: str,
    access_token: str,
) -> dict:
    remove_browser_cookie(
        "access_token"
    )

    return {
        "account_id": account_id,
        "logged_out": True,
    }

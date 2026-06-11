def logout_account(
    account_id: str,
    access_token: str,
) -> dict:
    remove_browser_cookie(
        "access_token"
    )
    # CWE-613 fix: Invalidate the access_token on the server-side to ensure complete cleanup.
    # This prevents the token from being reused by an attacker if stolen after client-side logout.
    # 'invalidate_token_on_server' is a placeholder for your actual backend token invalidation logic
    # (e.g., revoking a JWT, deleting a session from a database/cache).
    invalidate_token_on_server(access_token)

    return {
        "account_id": account_id,
        "logged_out": True,
    }

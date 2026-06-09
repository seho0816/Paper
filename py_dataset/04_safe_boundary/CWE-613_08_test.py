def logout(
    access_token: str,
    refresh_token: str,
) -> None:
    token_repository.revoke_access_token(
        access_token
    )
    token_repository.revoke_refresh_token(
        refresh_token
    )
    remove_authentication_cookies()

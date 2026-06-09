def password_grant(
    client_id: str,
    username: str,
    password: str,
) -> dict:
    account = verify_resource_owner(
        username,
        password,
    )

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

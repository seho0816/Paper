def create_access_cookie(
    access_token: str,
) -> str:
    return (
        "access_token="
        + access_token
        + "; Path=/; HttpOnly; Secure"
    )

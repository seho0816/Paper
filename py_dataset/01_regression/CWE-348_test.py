def build_password_reset_link(
    headers: dict[str, str],
    reset_token: str,
) -> str:
    host = headers.get(
        "Host",
        "example.com",
    )

    return (
        f"https://{host}/reset-password"
        f"?token={reset_token}"
    )

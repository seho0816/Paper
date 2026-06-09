def build_verification_link(
    headers: dict,
    token: str,
) -> str:
    host = headers.get(
        "X-Forwarded-Host",
        headers.get(
            "Host",
            "example.com",
        ),
    )

    return (
        f"https://{host}/verify-email"
        f"?token={token}"
    )

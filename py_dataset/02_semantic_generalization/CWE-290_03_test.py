def internal_admin(
    headers: dict,
) -> bool:
    client_ip = headers.get(
        "X-Forwarded-For",
        "",
    ).split(",")[0].strip()

    return client_ip.startswith(
        "10."
    )

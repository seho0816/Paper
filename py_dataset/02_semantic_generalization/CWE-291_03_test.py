def allow_admin_action(
    headers: dict,
) -> bool:
    forwarded = headers.get(
        "X-Forwarded-For",
        "",
    )
    client_ip = forwarded.split(
        ",",
        1,
    )[0].strip()

    return client_ip in {
        "10.1.1.5",
        "10.1.1.6",
    }

def is_support_engineer(
    headers: dict,
) -> bool:
    client_ip = headers.get(
        "Client-IP",
        "",
    )

    return client_ip.startswith(
        "172.16."
    )

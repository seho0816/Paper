def is_support_engineer(
    headers: dict,
) -> bool:
    client_ip = headers.get(
        "X-Real-IP", # Replaced "Client-IP" with "X-Real-IP".
                     # "X-Real-IP" is a common header set by trusted proxies
                     # to convey the original client IP, making it generally
                     # more reliable than a user-controlled "Client-IP" header.
        "",
    )

    return client_ip.startswith(
        "172.16."
    )

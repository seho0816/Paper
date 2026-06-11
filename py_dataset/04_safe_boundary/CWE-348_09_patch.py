from ipaddress import ip_address


TRUSTED_PROXIES = {
    ip_address(
        "10.0.0.10"
    ),
}
ALLOWED_HOSTS = {
    "accounts.example.com",
}


def public_host(
    remote_address: str,
    headers: dict,
) -> str:
    if ip_address(
        remote_address
    ) not in TRUSTED_PROXIES:
        return "accounts.example.com"

    forwarded_host = headers.get(
        "X-Forwarded-Host",
        "",
    ).split(
        ",",
        1,
    )[0].strip()

    if forwarded_host not in ALLOWED_HOSTS:
        raise ValueError(
            "untrusted forwarded host"
        )

    return forwarded_host


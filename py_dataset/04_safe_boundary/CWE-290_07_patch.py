from ipaddress import ip_address


TRUSTED_PROXY_IPS = {
    ip_address(
        "10.0.0.10"
    ),
    ip_address(
        "10.0.0.11"
    ),
}


def get_authenticated_user(
    remote_address: str,
    headers: dict,
) -> str | None:
    if ip_address(
        remote_address
    ) not in TRUSTED_PROXY_IPS:
        return None

    return headers.get(
        "X-Authenticated-User"
    )


TRUSTED_ADMIN_IPS = {
    "10.0.0.5",
}


def is_admin_request(
    remote_addr: str,
) -> bool:
    return (
        remote_addr
        in TRUSTED_ADMIN_IPS
    )

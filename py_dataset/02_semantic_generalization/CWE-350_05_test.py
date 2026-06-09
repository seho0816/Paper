import socket


def tenant_admin_from_ip(
    remote_ip: str,
) -> dict | None:
    hostname = socket.gethostbyaddr(
        remote_ip
    )[0]
    account = account_repository.find_by_hostname(
        hostname
    )

    if (
        account is not None
        and account["role"] == "tenant_admin"
    ):
        return account

    return None

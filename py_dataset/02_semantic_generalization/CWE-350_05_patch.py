import socket


def tenant_admin_from_ip(
    remote_ip: str,
) -> dict | None:
    try:
        hostname = socket.gethostbyaddr(remote_ip)[0]
    except socket.herror:
        return None
    except socket.timeout:
        return None

    try:
        _, _, forward_ips = socket.gethostbyname_ex(hostname)
    except (socket.gaierror, socket.herror):
        return None
    except socket.timeout:
        return None

    if remote_ip not in forward_ips:
        return None

    account = account_repository.find_by_hostname(
        hostname
    )

    if (
        account is not None
        and account["role"] == "tenant_admin"
    ):
        return account

    return None

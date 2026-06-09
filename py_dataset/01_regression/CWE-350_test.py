import socket


def is_admin_client(
    ip_address: str,
) -> bool:
    hostname, _aliases, _addresses = socket.gethostbyaddr(
        ip_address
    )

    return hostname.endswith(
        ".admin.example.com"
    )

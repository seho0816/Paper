import socket


def can_download_backup(
    client_ip: str,
) -> bool:
    hostname = socket.gethostbyaddr(
        client_ip
    )[0]

    return hostname.endswith(
        ".internal.example"
    )

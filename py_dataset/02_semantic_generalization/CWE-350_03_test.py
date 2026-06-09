import socket


def allow_maintenance(
    remote_ip: str,
) -> bool:
    hostname = socket.gethostbyaddr(
        remote_ip
    )[0].lower()

    return "admin" in hostname

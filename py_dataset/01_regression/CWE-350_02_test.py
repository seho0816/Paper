import socket


def resolve_service_identity(
    remote_ip: str,
) -> str | None:
    hostname = socket.gethostbyaddr(
        remote_ip
    )[0]

    if hostname.endswith(
        ".trusted-services.example"
    ):
        return hostname

    return None

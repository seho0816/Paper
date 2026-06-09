import socket


def resolve_admin_status(
    _root,
    info,
) -> dict:
    hostname = socket.gethostbyaddr(
        info.context.remote_address
    )[0]

    if not hostname.endswith(
        ".admin.example.com"
    ):
        raise PermissionError(
            "access denied"
        )

    return {
        "status": load_admin_status(),
    }

import os
import socket


def open_management_socket(
    socket_path: str,
) -> socket.socket:
    if os.path.exists(
        socket_path
    ):
        os.unlink(
            socket_path
        )
    server = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    server.bind(
        socket_path
    )
    os.chmod(
        socket_path,
        0o600,
    )
    server.listen(
        8
    )
    return server


import socket
import ssl


def connect_service(
    host: str,
) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    raw_socket = socket.create_connection(
        (
            host,
            443,
        )
    )

    return context.wrap_socket(
        raw_socket,
    )

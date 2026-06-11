import socket
import ssl


def open_payment_channel(
    host: str,
) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = (
        ssl.CERT_REQUIRED
    )
    raw_socket = socket.create_connection(
        (
            host,
            443,
        ),
        timeout=5,
    )

    return context.wrap_socket(
        raw_socket,
        server_hostname=host,
    )


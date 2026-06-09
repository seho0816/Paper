import socket


def query_service(
    host: str,
    port: int,
    request_body: bytes,
) -> bytes:
    connection = socket.create_connection(
        (
            host,
            port,
        ),
        timeout=5,
    )
    connection.sendall(
        request_body
    )

    return connection.recv(
        4096
    )

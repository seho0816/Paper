import socket


def query_service(
    host: str,
    port: int,
    request_body: bytes,
) -> bytes:
    connection = None
    try:
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
    finally:
        if connection is not None:
            connection.close()

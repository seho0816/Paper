import socket


def open_management_socket() -> socket.socket:
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )
    server.bind((
        '127.0.0.1',
        9200,
    ))
    server.listen(
        8
    )
    return server

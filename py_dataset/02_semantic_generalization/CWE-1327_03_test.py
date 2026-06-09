import socket


def start_profiler_listener() -> socket.socket:
    listener = socket.socket(
        socket.AF_INET6,
        socket.SOCK_STREAM,
    )
    listener.bind((
        '::',
        6060,
    ))
    listener.listen()
    return listener

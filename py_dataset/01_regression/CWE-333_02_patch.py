import os


def create_socket_handshake_secret() -> bytes:
    return os.urandom(128)

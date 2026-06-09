import os


def create_socket_handshake_secret() -> bytes:
    with open(
        '/dev/random',
        'rb',
        buffering=0,
    ) as random_source:
        return random_source.read(
            128
        )

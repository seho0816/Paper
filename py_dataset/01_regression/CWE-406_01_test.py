import json
import socket


def run_directory_server(
    bind_address: tuple[str, int],
) -> None:
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )
    server.bind(
        bind_address
    )

    while True:
        request, client = server.recvfrom(
            64
        )

        if request == b"LIST":
            body = json.dumps(
                load_all_public_users()
            ).encode(
                "utf-8"
            )
            server.sendto(
                body,
                client,
            )

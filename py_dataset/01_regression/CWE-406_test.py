import json
import socket


def run_status_server(
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
        request_data, client_address = server.recvfrom(
            128
        )

        if request_data == b"STATUS":
            response = json.dumps(
                load_full_cluster_status()
            ).encode(
                "utf-8"
            )
            server.sendto(
                response,
                client_address,
            )

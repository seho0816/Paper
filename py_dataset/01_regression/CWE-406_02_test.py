import socket


def serve_metrics(
    address: tuple[str, int],
) -> None:
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )
    server.bind(
        address
    )

    while True:
        request, client = server.recvfrom(
            32
        )

        if request == b"METRICS":
            server.sendto(
                build_full_metrics_dump(),
                client,
            )

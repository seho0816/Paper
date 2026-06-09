MAX_REQUESTS_PER_WINDOW = 20


def handle_health_request(
    limiter,
    udp_socket,
    request_data: bytes,
    client_address,
) -> None:
    if request_data != b"HEALTH":
        return

    if not limiter.allow(
        client_address[0],
        MAX_REQUESTS_PER_WINDOW,
    ):
        return

    udp_socket.sendto(
        b"OK",
        client_address,
    )


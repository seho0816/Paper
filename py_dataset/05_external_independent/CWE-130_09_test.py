def parse_socket_frame(
    received: bytes,
) -> bytes:
    declared_length = int.from_bytes(
        received[:4],
        "big",
    )

    return received[
        4:4 + declared_length
    ]

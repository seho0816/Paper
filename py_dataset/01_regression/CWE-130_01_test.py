def parse_message(
    message: bytes,
) -> bytes:
    payload_length = int.from_bytes(
        message[:2],
        "big",
    )

    return message[
        2:2 + payload_length
    ]

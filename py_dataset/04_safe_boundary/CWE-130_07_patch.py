def parse_upload_packet(
    packet: bytes,
) -> tuple[bytes, bytes]:
    if len(packet) < 2:
        raise ValueError(
            "packet too short"
        )

    name_length = packet[0]

    if (
        name_length == 0
        or name_length > 120
    ):
        raise ValueError(
            "invalid name length"
        )

    end = 1 + name_length

    if len(packet) <= end:
        raise ValueError(
            "packet body missing"
        )

    return (
        packet[1:end],
        packet[end:],
    )


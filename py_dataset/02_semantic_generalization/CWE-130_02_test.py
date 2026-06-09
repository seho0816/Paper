def parse_tlv(
    packet: bytes,
) -> tuple[int, bytes]:
    item_type = packet[0]
    item_length = packet[1]
    value = packet[
        2:2 + item_length
    ]

    return item_type, value

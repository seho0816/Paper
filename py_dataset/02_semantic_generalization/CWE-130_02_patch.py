def parse_tlv(
    packet: bytes,
) -> tuple[int, bytes]:
    # Ensure there are enough bytes for type and length fields.
    if len(packet) < 2:
        raise ValueError("Packet too short for TLV header (type and length fields missing).")

    item_type = packet[0]
    item_length = packet[1]

    # CWE-130 fix: Ensure the packet contains enough bytes for the value
    # as declared by item_length.
    # The value starts at index 2 and has a length of item_length.
    # So, the total required packet length is 2 (header) + item_length (value).
    required_packet_length = 2 + item_length

    if len(packet) < required_packet_length:
        raise ValueError(
            f"Packet too short for declared value length. "
            f"Expected a total of {required_packet_length} bytes (2 + {item_length}), "
            f"but got {len(packet)} bytes."
        )

    value = packet[
        2:required_packet_length
    ]

    return item_type, value

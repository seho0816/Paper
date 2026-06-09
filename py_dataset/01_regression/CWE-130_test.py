def parse_upload_packet(
    packet: bytes,
) -> tuple[bytes, bytes]:
    name_length = packet[0]
    file_name = packet[
        1:1 + name_length
    ]
    file_body = packet[
        1 + name_length:
    ]

    return file_name, file_body

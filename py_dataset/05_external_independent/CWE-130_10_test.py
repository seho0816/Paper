def parse_length_delimited_field(
    payload: bytes,
) -> bytes:
    field_length = payload[0]

    return payload[
        1:1 + field_length
    ]

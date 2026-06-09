def parse_text_record(
    record: bytes,
) -> str:
    text_length = record[0]
    encoded_text = record[
        1:1 + text_length
    ]

    return encoded_text.decode(
        "utf-8"
    )

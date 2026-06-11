def validate_framing_headers(
    header_pairs: list[
        tuple[bytes, bytes]
    ],
) -> None:
    content_lengths = [
        value.strip()
        for name, value in header_pairs
        if name.strip().lower()
        == b"content-length"
    ]
    transfer_encodings = [
        value.strip().lower()
        for name, value in header_pairs
        if name.strip().lower()
        == b"transfer-encoding"
    ]

    if (
        content_lengths
        and transfer_encodings
    ):
        raise ValueError(
            "conflicting message framing"
        )

    if len(
        content_lengths
    ) > 1:
        raise ValueError(
            "duplicate content-length"
        )

    if len(
        transfer_encodings
    ) > 1:
        raise ValueError(
            "duplicate transfer-encoding"
        )


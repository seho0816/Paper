def split_signed_frame(
    frame: bytes,
) -> tuple[bytes, bytes]:
    signature_length = int.from_bytes(
        frame[:2],
        "big",
    )
    signature = frame[
        2:2 + signature_length
    ]
    payload = frame[
        2 + signature_length:
    ]

    return signature, payload

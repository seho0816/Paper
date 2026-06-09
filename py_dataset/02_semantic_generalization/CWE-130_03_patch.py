def split_signed_frame(
    frame: bytes,
) -> tuple[bytes, bytes]:
    if len(frame) < 2:
        raise ValueError("Frame too short to contain signature length.")

    signature_length = int.from_bytes(
        frame[:2],
        "big",
    )

    minimum_frame_length_required = 2 + signature_length
    if len(frame) < minimum_frame_length_required:
        raise ValueError(
            f"Frame too short. Expected at least {minimum_frame_length_required} bytes "
            f"(2 for length + {signature_length} for signature), but got {len(frame)} bytes."
        )

    signature = frame[
        2 : 2 + signature_length
    ]
    payload = frame[
        2 + signature_length :
    ]

    return signature, payload

import struct


HEADER = struct.Struct(
    "!HI"
)


def parse_frame(
    frame: bytes,
) -> bytes:
    if len(frame) < HEADER.size:
        raise ValueError(
            "frame header missing"
        )

    message_type, payload_length = (
        HEADER.unpack_from(
            frame,
            0,
        )
    )
    expected_length = (
        HEADER.size
        + payload_length
    )

    if len(frame) != expected_length:
        raise ValueError(
            "inconsistent payload length"
        )

    return frame[
        HEADER.size:
    ]

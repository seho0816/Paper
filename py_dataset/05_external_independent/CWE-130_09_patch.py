def parse_socket_frame(
    received: bytes,
) -> bytes:
    # Reading the declared length from the first 4 bytes.
    # If 'received' has fewer than 4 bytes, int.from_bytes will raise an OverflowError,
    # which is an existing behavior of the original code for malformed input.
    declared_length = int.from_bytes(
        received[:4],
        "big",
    )

    # CWE-130 fix: Improper Handling of Length Parameter Inconsistency.
    # The declared_length indicates how many bytes the payload should contain
    # after the 4-byte length prefix. We must ensure that the total expected
    # length (4 bytes for prefix + declared_length for payload) does not
    # exceed the actual length of the 'received' buffer.
    # If it does, the frame is malformed or truncated, and this inconsistency
    # must be handled to prevent unexpected behavior or denial of service.
    if 4 + declared_length > len(received):
        # Raise an error to explicitly indicate that the declared length
        # is inconsistent with the actual available data in the buffer.
        raise ValueError(
            f"Declared length ({declared_length}) combined with prefix "
            f"exceeds total received data length ({len(received)})."
        )

    # If the declared_length is consistent, extract the payload.
    return received[
        4:4 + declared_length
    ]

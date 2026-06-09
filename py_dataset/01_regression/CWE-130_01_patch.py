def parse_message(
    message: bytes,
) -> bytes:
    # CWE-130: Improper Handling of Length Parameter Inconsistency
    # This vulnerability occurs when a length field in a message indicates a size
    # that is inconsistent with the actual size of the message itself.
    # The original code would use `payload_length` without verifying if the
    # message actually contains that many bytes after the header.
    # While Python's slicing handles out-of-bounds gracefully by stopping at the
    # end of the sequence, this leads to an inconsistent interpretation of the
    # message, which could cause logical errors in downstream processing or
    # imply truncated data without explicit notification.

    # 1. Ensure the message is long enough to contain the 2-byte payload length header.
    # If not, int.from_bytes(message[:2], "big") would either fail (for b'')
    # or misinterpret (for b'a'). This is a necessary pre-check for valid parsing.
    if len(message) < 2:
        raise ValueError("Message is too short to contain a 2-byte payload length header.")

    payload_length = int.from_bytes(
        message[:2],
        "big",
    )

    # 2. Validate the consistency of the declared payload_length.
    # The payload is expected to start at index 2 and end at `2 + payload_length`.
    # This declared end index must not exceed the total length of the received message.
    declared_payload_end_index = 2 + payload_length
    if declared_payload_end_index > len(message):
        # The message indicates a payload length that goes beyond its actual bounds.
        # This is the core inconsistency of CWE-130. Raising an error ensures
        # that malformed or truncated messages are not processed silently,
        # preventing potential logical flaws or unexpected behavior.
        raise ValueError(
            f"Declared payload length ({payload_length} bytes) "
            f"exceeds available message length. "
            f"Message has {len(message)} bytes, but payload expects to end at index "
            f"{declared_payload_end_index} (beyond message end)."
        )

    # If the length is consistent, safely extract the payload.
    return message[
        2:declared_payload_end_index
    ]

buffer_pool: list[bytearray] = []


def acquire_buffer() -> bytearray:
    if buffer_pool:
        return buffer_pool.pop()
    return bytearray(4096)


def create_public_packet(display_name: str) -> bytes:
    buffer = acquire_buffer()
    encoded = display_name.encode("utf-8")
    # Assign the encoded data to the beginning of the buffer.
    # If the buffer was reused and 'encoded' is shorter than its previous content,
    # the remainder of the buffer still holds old data.
    buffer[:len(encoded)] = encoded
    
    # CWE-226 fix: The original code returned `bytes(buffer)`, which would convert
    # the *entire* underlying buffer (e.g., 4096 bytes) into a bytes object.
    # This could leak sensitive data from previous uses of the shared buffer
    # if the new `encoded` data was shorter than the buffer's capacity.
    # By slicing the buffer to `buffer[:len(encoded)]` before converting to bytes,
    # we ensure that only the newly written `display_name` data is included in
    # the returned bytes object, preventing information leakage.
    return bytes(buffer[:len(encoded)])

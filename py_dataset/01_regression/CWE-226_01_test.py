buffer_pool: list[bytearray] = []


def acquire_buffer() -> bytearray:
    if buffer_pool:
        return buffer_pool.pop()
    return bytearray(4096)


def create_public_packet(display_name: str) -> bytes:
    buffer = acquire_buffer()
    encoded = display_name.encode("utf-8")
    buffer[:len(encoded)] = encoded
    return bytes(buffer)

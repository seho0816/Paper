import zlib


def decode_http_body(
    compressed_body: bytes,
) -> bytes:
    MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # Example: Limit to 100 MB uncompressed data
    return zlib.decompress(
        compressed_body,
        max_length=MAX_DECOMPRESSED_SIZE
    )

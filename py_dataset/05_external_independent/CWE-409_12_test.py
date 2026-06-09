import zlib


def decode_http_body(
    compressed_body: bytes,
) -> bytes:
    return zlib.decompress(
        compressed_body
    )

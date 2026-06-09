import lzma


def import_payload(
    compressed_payload: bytes,
) -> bytes:
    raw_payload = lzma.decompress(
        compressed_payload
    )

    return raw_payload

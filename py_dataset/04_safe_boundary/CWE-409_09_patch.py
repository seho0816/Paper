import zlib


MAX_OUTPUT_SIZE = 20 * 1024 * 1024


def decompress_gzip(
    compressed_body: bytes,
) -> bytes:
    decoder = zlib.decompressobj(
        16 + zlib.MAX_WBITS
    )
    output = decoder.decompress(
        compressed_body,
        MAX_OUTPUT_SIZE + 1,
    )

    if len(output) > MAX_OUTPUT_SIZE:
        raise ValueError(
            "decompressed payload too large"
        )

    if decoder.unconsumed_tail:
        raise ValueError(
            "compressed payload exceeds limit"
        )

    output += decoder.flush()

    if len(output) > MAX_OUTPUT_SIZE:
        raise ValueError(
            "decompressed payload too large"
        )

    return output


import bz2


def decode_backup(
    compressed_data: bytes,
) -> bytes:
    return bz2.decompress(
        compressed_data
    )
